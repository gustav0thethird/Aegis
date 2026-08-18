"""
self_service.py — Team self-service and read-only views.
"""

import secrets as secrets_lib
import uuid
from datetime import (
    datetime,
    timezone,
)
from typing import (
    List,
    Optional,
)

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis import secret_cache
from aegis.database import get_db
from aegis.deps import (
    _authenticate_team_webhook,
    _generate_key,
    _hash_key,
    _require_any_user,
    _resolve_user_team,
    _validated_url,
    logger,
)
from aegis.models import (
    AuditLog,
    Registry,
    Team,
    TeamRegistry,
    TeamRegistryKey,
    Webhook,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# User role — read-only team view
# ---------------------------------------------------------------------------

def _build_team_dashboard(team: Team) -> dict:
    """Shared helper: build the team payload for dashboard endpoints."""
    active_keys = {
        str(k.registry_id): k
        for k in team.keys if k.revoked_at is None
    }
    registries  = []
    all_objects = {}
    for tr in team.registry_links:
        reg        = tr.registry
        reg_objects = [ro.object_name for ro in reg.registry_entries]
        key_row    = active_keys.get(str(reg.id))
        registries.append({
            "id":          str(reg.id),
            "name":        reg.name,
            "objects":     reg_objects,
            "key_preview": key_row.key_preview if key_row else None,
            "expires_at":  key_row.expires_at.isoformat() if key_row and key_row.expires_at else None,
        })
        for ro in reg.registry_entries:
            obj = ro.object
            all_objects[obj.name] = {
                "name": obj.name, "vendor": obj.vendor,
                "path": obj.path, "platform": obj.platform, "safe": obj.safe,
            }
    return {
        "id":         str(team.id),
        "name":       team.name,
        "registries": registries,
        "objects":    list(all_objects.values()),
    }


@router.get("/api/my-teams")
def api_my_teams(session: dict = Depends(_require_any_user), db: Session = Depends(get_db)):
    if session["role"] == "admin":
        raise HTTPException(status_code=400, detail="Admins use the admin API")
    # Support both old single team_id and new team_ids list in session
    team_ids = session.get("team_ids") or []
    if not team_ids and session.get("team_id"):
        team_ids = [session["team_id"]]
    if not team_ids:
        return {"teams": []}
    teams = db.query(Team).filter(
        Team.id.in_([uuid.UUID(tid) for tid in team_ids])
    ).all()
    return {"teams": [_build_team_dashboard(t) for t in teams]}


@router.get("/api/my-team")
def api_my_team(session: dict = Depends(_require_any_user), db: Session = Depends(get_db)):
    """Backward-compatible single-team endpoint — returns first team."""
    data  = api_my_teams(session=session, db=db)
    teams = data.get("teams", [])
    if not teams:
        return {"team": None, "registries": [], "objects": []}
    t = teams[0]
    return {"team": {"id": t["id"], "name": t["name"]},
            "name": t["name"],
            "registries": t["registries"],
            "objects":    t["objects"]}


# ---------------------------------------------------------------------------
# Team self-service: webhooks, metrics, inbound webhook
# ---------------------------------------------------------------------------


class TeamWebhookRequest(BaseModel):
    url: Optional[str] = None
    enabled: bool = True
    events: List[str] = []
    signing_enabled: bool = False
    secret: Optional[str] = None
    # Notification channels
    slack_webhook_url: Optional[str] = None
    ms_teams_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None


@router.get("/api/my-webhook")
def api_get_my_webhook(
    team_id: Optional[str] = None,
    session: dict = Depends(_require_any_user),
    db: Session = Depends(get_db),
):
    team = _resolve_user_team(session, db, team_id)
    wh = team.webhook
    return {
        "team_id":   str(team.id),
        "team_name": team.name,
        "webhook": {
            "id":              str(wh.id) if wh else None,
            "url":             wh.url if wh else None,
            "enabled":         wh.enabled if wh else False,
            "events":          wh.events if wh else [],
            "signing_enabled": wh.signing_enabled if wh else False,
            "has_secret":      bool(wh and wh.secret),
        } if wh else None,
        "notifications": {
            "slack_webhook_url":    team.slack_webhook_url,
            "ms_teams_webhook_url": team.ms_teams_webhook_url,
            "discord_webhook_url":  team.discord_webhook_url,
        },
        # Inbound webhook URL — external systems POST here to trigger Aegis events
        "inbound_url": f"/api/inbound/{team.id}",
    }


@router.put("/api/my-webhook")
def api_put_my_webhook(
    req: TeamWebhookRequest,
    team_id: Optional[str] = None,
    session: dict = Depends(_require_any_user),
    db: Session = Depends(get_db),
):
    """Create or update webhook config + notification channels for user's team."""
    team = _resolve_user_team(session, db, team_id)

    # Every URL below is requested server-side, so validate before storing.
    webhook_url = _validated_url(req.url, "url")

    # Update notification channels on Team
    team.slack_webhook_url    = _validated_url(req.slack_webhook_url, "slack_webhook_url")
    team.ms_teams_webhook_url = _validated_url(req.ms_teams_webhook_url, "ms_teams_webhook_url")
    team.discord_webhook_url  = _validated_url(req.discord_webhook_url, "discord_webhook_url")

    # Upsert HTTP webhook if URL provided
    if webhook_url:
        from aegis.webhook import ALL_EVENTS
        bad = [e for e in req.events if e not in ALL_EVENTS]
        if bad:
            raise HTTPException(status_code=400, detail=f"Unknown events: {bad}")

        wh = team.webhook
        if wh:
            wh.url             = webhook_url
            wh.enabled         = req.enabled
            wh.events          = req.events
            wh.signing_enabled = req.signing_enabled
            if req.secret is not None:
                wh.secret = req.secret or secrets_lib.token_hex(32)
        else:
            wh = Webhook(
                team_id         = team.id,
                url             = webhook_url,
                enabled         = req.enabled,
                events          = req.events,
                signing_enabled = req.signing_enabled,
                secret          = req.secret or (secrets_lib.token_hex(32) if req.signing_enabled else None),
                created_by      = session["username"],
            )
            db.add(wh)

    db.commit()
    return {"ok": True}


@router.delete("/api/my-webhook", status_code=204)
def api_delete_my_webhook(
    team_id: Optional[str] = None,
    session: dict = Depends(_require_any_user),
    db: Session = Depends(get_db),
):
    team = _resolve_user_team(session, db, team_id)
    if team.webhook:
        db.delete(team.webhook)
        db.commit()


@router.get("/api/my-metrics")
def api_my_metrics(
    team_id: Optional[str] = None,
    session: dict = Depends(_require_any_user),
    db: Session = Depends(get_db),
):
    """Team-scoped usage metrics: audit counts, key counts, recent activity."""
    team = _resolve_user_team(session, db, team_id)
    tid  = team.id

    from sqlalchemy import func as sa_f
    # Audit counts for this team
    audit_counts = dict(
        db.query(AuditLog.outcome, sa_f.count(AuditLog.id))
          .filter(AuditLog.team_id == tid)
          .group_by(AuditLog.outcome)
          .all()
    )
    total_requests = sum(audit_counts.values())

    # Recent audit entries (last 20)
    recent = db.query(AuditLog).filter(AuditLog.team_id == tid) \
               .order_by(AuditLog.timestamp.desc()).limit(20).all()

    # Key stats
    active_keys   = db.query(TeamRegistryKey).filter(
        TeamRegistryKey.team_id   == tid,
        TeamRegistryKey.revoked_at == None,  # noqa: E711
    ).count()
    revoked_keys  = db.query(TeamRegistryKey).filter(
        TeamRegistryKey.team_id   == tid,
        TeamRegistryKey.revoked_at != None,  # noqa: E711
    ).count()

    now = datetime.now(timezone.utc)
    from datetime import timedelta
    expiring_soon = db.query(TeamRegistryKey).filter(
        TeamRegistryKey.team_id   == tid,
        TeamRegistryKey.revoked_at == None,  # noqa: E711
        TeamRegistryKey.expires_at != None,  # noqa: E711
        TeamRegistryKey.expires_at >  now,
        TeamRegistryKey.expires_at <= now + timedelta(days=30),
    ).count()

    return {
        "team_id":       str(tid),
        "team_name":     team.name,
        "requests": {
            "total":   total_requests,
            "success": audit_counts.get("success", 0),
            "denied":  audit_counts.get("denied", 0),
            "error":   audit_counts.get("error", 0),
        },
        "keys": {
            "active":        active_keys,
            "revoked":       revoked_keys,
            "expiring_soon": expiring_soon,
        },
        "recent_audit": [
            {
                "timestamp":     e.timestamp.isoformat() if e.timestamp else None,
                "event":         e.event,
                "outcome":       e.outcome,
                "registry_name": e.registry_name,
                "source_ip":     e.source_ip,
                "key_preview":   e.key_preview,
            }
            for e in recent
        ],
    }


class InboundWebhookRequest(BaseModel):
    action: str                          # e.g. "rotate_key", "ping"
    registry_id: Optional[str] = None
    detail: Optional[str] = None


@router.post("/api/inbound/{team_id_str}")
def api_inbound_webhook(
    team_id_str: str,
    req: InboundWebhookRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Inbound webhook receiver — external CI/CD systems POST here to trigger Aegis actions.
    Authenticated via Authorization: Bearer <webhook_signing_secret>.
    URL is auto-generated per team based on team ID.
    """
    # Same credential and checks as scan ingest — see _authenticate_team_webhook.
    team = _authenticate_team_webhook(db, team_id_str, request)
    tid = team.id

    if req.action == "ping":
        return {"ok": True, "team": team.name, "message": "pong"}

    if req.action == "rotate_key":
        if not req.registry_id:
            raise HTTPException(status_code=400, detail="registry_id required for rotate_key")
        # Delegate to the existing rotation logic
        try:
            reg_uuid = uuid.UUID(req.registry_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid registry_id") from None
        reg = db.get(Registry, reg_uuid)
        if not reg:
            raise HTTPException(status_code=404, detail="Registry not found")
        # Verify team has access
        tr = db.query(TeamRegistry).filter(
            TeamRegistry.team_id == tid,
            TeamRegistry.registry_id == reg_uuid,
        ).first()
        if not tr:
            raise HTTPException(status_code=403, detail="Team does not have access to that registry")

        # Rotate key — same generator, hash and preview format as every other
        # rotation path, so inbound-rotated keys are indistinguishable downstream.
        new_raw     = _generate_key()
        new_hash    = _hash_key(new_raw)
        new_preview = new_raw[:10] + "..."

        old_keys = db.query(TeamRegistryKey).filter(
            TeamRegistryKey.team_id    == tid,
            TeamRegistryKey.registry_id == reg_uuid,
            TeamRegistryKey.revoked_at == None,  # noqa: E711
        ).all()
        for k in old_keys:
            k.revoked_at = datetime.now(timezone.utc)
            secret_cache.invalidate(k.key_hash)

        new_key = TeamRegistryKey(
            team_id=tid, registry_id=reg_uuid,
            key_hash=new_hash, key_preview=new_preview,
        )
        db.add(new_key)
        db.commit()
        logger.info("Inbound webhook rotated key team=%s registry=%s", tid, reg_uuid)
        return {"ok": True, "key_preview": new_preview, "new_key": new_raw}

    raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")


