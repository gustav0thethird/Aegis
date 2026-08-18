"""
metrics.py — Prometheus metrics.
"""

from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from aegis.database import get_db
from aegis.deps import (
    _require_any_user,
    _resolve_user_team,
)
from aegis.models import (
    AuditLog,
    Object,
    Registry,
    Team,
    TeamRegistryKey,
    WebhookLog,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

@router.get("/api/my-metrics/prometheus", include_in_schema=False)
def api_my_metrics_prometheus(
    team_id: Optional[str] = None,
    session: dict = Depends(_require_any_user),
    db: Session = Depends(get_db),
):
    """Team-scoped Prometheus metrics — teams can wire this into their own Grafana."""
    from sqlalchemy import func as sa_func
    team = _resolve_user_team(session, db, team_id)
    tid  = team.id
    tname = team.name.replace('"', '\\"')

    lines = [f"# Aegis team metrics — {team.name}", ""]

    for outcome, count in db.query(AuditLog.outcome, sa_func.count(AuditLog.id)) \
            .filter(AuditLog.team_id == tid).group_by(AuditLog.outcome).all():
        lines.append(f'aegis_team_audit_total{{team="{tname}",outcome="{outcome}"}} {count}')

    active_keys   = db.query(TeamRegistryKey).filter(
        TeamRegistryKey.team_id == tid, TeamRegistryKey.revoked_at.is_(None)).count()
    revoked_keys  = db.query(TeamRegistryKey).filter(
        TeamRegistryKey.team_id == tid, TeamRegistryKey.revoked_at.isnot(None)).count()
    lines.append(f'aegis_team_keys_total{{team="{tname}",state="active"}} {active_keys}')
    lines.append(f'aegis_team_keys_total{{team="{tname}",state="revoked"}} {revoked_keys}')

    return StreamingResponse(iter(["\n".join(lines) + "\n"]), media_type="text/plain; version=0.0.4")


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics(db: Session = Depends(get_db)):
    """Prometheus-format metrics endpoint."""
    from sqlalchemy import func as sa_func

    lines = ["# Aegis metrics", ""]

    # Audit log counters by outcome
    lines.append("# HELP aegis_audit_total Total audit log entries by outcome")
    lines.append("# TYPE aegis_audit_total counter")
    for outcome, count in db.query(AuditLog.outcome, sa_func.count(AuditLog.id)).group_by(AuditLog.outcome).all():
        lines.append(f'aegis_audit_total{{outcome="{outcome}"}} {count}')

    # Team / registry / object counts
    lines.append("")
    lines.append("# HELP aegis_objects_total Total secret objects")
    lines.append("# TYPE aegis_objects_total gauge")
    lines.append(f"aegis_objects_total {db.query(Object).count()}")

    lines.append("# HELP aegis_registries_total Total registries")
    lines.append("# TYPE aegis_registries_total gauge")
    lines.append(f"aegis_registries_total {db.query(Registry).count()}")

    lines.append("# HELP aegis_teams_total Total teams")
    lines.append("# TYPE aegis_teams_total gauge")
    lines.append(f"aegis_teams_total {db.query(Team).count()}")

    # Active vs revoked keys
    active_keys  = db.query(TeamRegistryKey).filter(TeamRegistryKey.revoked_at.is_(None)).count()
    revoked_keys = db.query(TeamRegistryKey).filter(TeamRegistryKey.revoked_at.isnot(None)).count()
    lines.append("# HELP aegis_keys_total API keys by state")
    lines.append("# TYPE aegis_keys_total gauge")
    lines.append(f'aegis_keys_total{{state="active"}} {active_keys}')
    lines.append(f'aegis_keys_total{{state="revoked"}} {revoked_keys}')

    # Webhook delivery stats
    lines.append("# HELP aegis_webhook_deliveries_total Webhook delivery attempts by success")
    lines.append("# TYPE aegis_webhook_deliveries_total counter")
    for success, count in db.query(WebhookLog.success, sa_func.count(WebhookLog.id)).group_by(WebhookLog.success).all():
        label = "success" if success else "failure"
        lines.append(f'aegis_webhook_deliveries_total{{result="{label}"}} {count}')

    # Policy violations (audit outcome=denied)
    denied = db.query(AuditLog).filter(AuditLog.outcome == "denied").count()
    lines.append("# HELP aegis_policy_violations_total Requests blocked by policy")
    lines.append("# TYPE aegis_policy_violations_total counter")
    lines.append(f"aegis_policy_violations_total {denied}")

    return StreamingResponse(
        iter(["\n".join(lines) + "\n"]),
        media_type="text/plain; version=0.0.4",
    )


