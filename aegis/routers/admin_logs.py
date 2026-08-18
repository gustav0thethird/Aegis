"""
admin_logs.py — Admin change log, audit log and CSV exports.
"""

import csv
import io
from datetime import (
    datetime,
    timezone,
)
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from aegis.database import get_db
from aegis.deps import _require_admin
from aegis.models import (
    AuditLog,
    ChangeLog,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Admin API — change log
# ---------------------------------------------------------------------------

@router.get("/admin/api/changelog")
def admin_changelog(
    session: dict = Depends(_require_admin),
    page: int = 1, limit: int = 50,
    entity_type: Optional[str] = None,
    entity_id:   Optional[str] = None,
    action:      Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(ChangeLog).order_by(ChangeLog.timestamp.desc())
    if entity_type:
        q = q.filter(ChangeLog.entity_type == entity_type)
    if entity_id:
        q = q.filter(ChangeLog.entity_id   == entity_id)
    if action:
        q = q.filter(ChangeLog.action       == action)
    total = q.count()
    rows  = q.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total, "page": page, "limit": limit,
        "rows": [{
            "id": row.id, "timestamp": row.timestamp.isoformat(),
            "action": row.action, "entity_type": row.entity_type,
            "entity_id": row.entity_id, "entity_name": row.entity_name,
            "detail": row.detail, "diff": row.diff,
            "performed_by": row.performed_by,
        } for row in rows],
    }


# ---------------------------------------------------------------------------
# Admin API — audit log
# ---------------------------------------------------------------------------

@router.get("/admin/api/audit")
def admin_audit_log(
    session: dict = Depends(_require_admin),
    page: int = 1, limit: int = 50,
    registry_id:   Optional[str] = None,
    change_number: Optional[str] = None,
    outcome:       Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    if registry_id:
        q = q.filter(AuditLog.registry_id == registry_id)
    if change_number:
        q = q.filter(AuditLog.change_number == change_number)
    if outcome:
        q = q.filter(AuditLog.outcome == outcome)
    total = q.count()
    rows  = q.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total, "page": page, "limit": limit,
        "rows": [{
            "id": row.id, "timestamp": row.timestamp.isoformat(),
            "event": row.event, "outcome": row.outcome,
            "change_number": row.change_number,
            "registry_name": row.registry_name,
            "registry_id": str(row.registry_id) if row.registry_id else None,
            "team_name": row.team_name,
            "team_id": str(row.team_id) if row.team_id else None,
            "objects": row.objects or [], "key_preview": row.key_preview,
            "source_ip": row.source_ip, "error_detail": row.error_detail,
        } for row in rows],
    }


# ---------------------------------------------------------------------------
# CSV exports
# ---------------------------------------------------------------------------

@router.get("/admin/api/audit/export")
def admin_audit_export(
    outcome:       Optional[str] = None,
    change_number: Optional[str] = None,
    registry_id:   Optional[str] = None,
    session: dict = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    if outcome:
        q = q.filter(AuditLog.outcome == outcome)
    if change_number:
        q = q.filter(AuditLog.change_number == change_number)
    if registry_id:
        q = q.filter(AuditLog.registry_id == registry_id)
    rows = q.all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "event", "outcome", "change_number",
                "team_name", "registry_name", "objects", "key_preview",
                "source_ip", "user_agent", "error_detail"])
    for r in rows:
        w.writerow([
            r.timestamp.isoformat(), r.event, r.outcome,
            r.change_number or "", r.team_name or "", r.registry_name or "",
            "|".join(r.objects or []), r.key_preview or "",
            r.source_ip or "", r.user_agent or "", r.error_detail or "",
        ])
    buf.seek(0)
    filename = f"aegis-audit-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/admin/api/changelog/export")
def admin_changelog_export(
    entity_type: Optional[str] = None,
    action:      Optional[str] = None,
    session: dict = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(ChangeLog).order_by(ChangeLog.timestamp.desc())
    if entity_type:
        q = q.filter(ChangeLog.entity_type == entity_type)
    if action:
        q = q.filter(ChangeLog.action == action)
    rows = q.all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "action", "entity_type", "entity_name", "entity_id", "detail", "performed_by"])
    for r in rows:
        w.writerow([
            r.timestamp.isoformat(), r.action, r.entity_type,
            r.entity_name, r.entity_id, r.detail or "", r.performed_by,
        ])
    buf.seek(0)
    filename = f"aegis-changelog-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


