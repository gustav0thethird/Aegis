"""
admin_config.py — Admin settings and policies.
"""

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
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis.database import get_db
from aegis.deps import (
    _compute_diff,
    _get_policy,
    _get_registry,
    _get_team,
    _require_admin,
    _write_change,
)
from aegis.models import (
    Policy,
    Registry,
    Setting,
    TeamRegistryKey,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Admin API — settings
# ---------------------------------------------------------------------------

EDITABLE_SETTINGS = {
    "siem_destinations", "splunk_hec_url", "splunk_hec_token",
    "s3_log_bucket", "dd_api_key", "rate_limit_rpm",
    "change_number_required", "session_ttl_hours", "log_retention_days",
}


@router.get("/admin/api/settings")
def admin_get_settings(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    rows = db.query(Setting).all()
    return {r.key: r.value for r in rows}


class SettingsPatch(BaseModel):
    settings: dict


@router.put("/admin/api/settings")
def admin_update_settings(req: SettingsPatch, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    unknown = set(req.settings) - EDITABLE_SETTINGS
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown settings: {unknown}")
    diff = {}
    for key, value in req.settings.items():
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            diff[key] = {"from": row.value, "to": str(value)}
            row.value = str(value)
            row.updated_at = now
            row.updated_by = session["username"]
        else:
            diff[key] = {"from": None, "to": str(value)}
            db.add(Setting(key=key, value=str(value), updated_by=session["username"]))
    db.commit()
    _write_change(db, "updated", "settings", "settings", "settings",
                  None, session["username"], diff=diff)
    return {r.key: r.value for r in db.query(Setting).all()}


# ---------------------------------------------------------------------------
# Admin API — policies
# ---------------------------------------------------------------------------

class PolicyRequest(BaseModel):
    ip_allowlist:   Optional[List[str]] = None   # CIDRs
    allowed_from:   Optional[str]       = None   # "HH:MM" UTC
    allowed_to:     Optional[str]       = None   # "HH:MM" UTC
    cn_required:    Optional[bool]      = None   # None = inherit global
    rate_limit_rpm: Optional[int]       = None   # None = inherit global
    max_key_days:   Optional[int]       = None   # None = no expiry


def _parse_time(s: Optional[str]):
    if s is None:
        return None
    from datetime import time as dt_time
    try:
        h, m = s.split(":")
        return dt_time(int(h), int(m))
    except Exception:
        raise HTTPException(status_code=422, detail=f"Invalid time format '{s}', expected HH:MM") from None


def _policy_response(p: Policy) -> dict:
    return {
        "id":             str(p.id),
        "entity_type":    p.entity_type,
        "entity_id":      str(p.entity_id),
        "ip_allowlist":   p.ip_allowlist,
        "allowed_from":   p.allowed_from.strftime("%H:%M") if p.allowed_from else None,
        "allowed_to":     p.allowed_to.strftime("%H:%M")   if p.allowed_to   else None,
        "cn_required":    p.cn_required,
        "rate_limit_rpm": p.rate_limit_rpm,
        "max_key_days":   p.max_key_days,
        "updated_at":     p.updated_at.isoformat(),
        "updated_by":     p.updated_by,
    }


@router.get("/admin/api/registries/{reg_id}/policy")
def admin_get_registry_policy(reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    p   = _get_policy(db, "registry", reg.id)
    return _policy_response(p) if p else {}


@router.put("/admin/api/registries/{reg_id}/policy", status_code=200)
def admin_set_registry_policy(reg_id: str, req: PolicyRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg    = _get_registry(db, reg_id)
    before = {}
    p      = _get_policy(db, "registry", reg.id)
    if p:
        before = _policy_response(p)
    else:
        p = Policy(entity_type="registry", entity_id=reg.id)
        db.add(p)

    p.ip_allowlist   = req.ip_allowlist
    p.allowed_from   = _parse_time(req.allowed_from)
    p.allowed_to     = _parse_time(req.allowed_to)
    p.cn_required    = req.cn_required
    p.rate_limit_rpm = req.rate_limit_rpm
    p.max_key_days   = req.max_key_days
    p.updated_at     = datetime.now(timezone.utc)
    p.updated_by     = session["username"]
    db.commit()
    db.refresh(p)

    # If max_key_days changed, update expires_at on all active keys for this registry
    if req.max_key_days is not None:
        _apply_key_expiry_to_registry(db, reg, req.max_key_days)

    after = _policy_response(p)
    _write_change(db, "updated", "registry", str(reg.id), reg.name,
                  "policy updated", session["username"],
                  diff=_compute_diff(before, after))
    return after


@router.delete("/admin/api/registries/{reg_id}/policy", status_code=204)
def admin_delete_registry_policy(reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    p   = _get_policy(db, "registry", reg.id)
    if p:
        db.delete(p)
        db.commit()
        _write_change(db, "deleted", "registry", str(reg.id), reg.name,
                      "policy removed", session["username"])


@router.get("/admin/api/teams/{team_id}/policy")
def admin_get_team_policy(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    p    = _get_policy(db, "team", team.id)
    return _policy_response(p) if p else {}


@router.put("/admin/api/teams/{team_id}/policy", status_code=200)
def admin_set_team_policy(team_id: str, req: PolicyRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team   = _get_team(db, team_id)
    before = {}
    p      = _get_policy(db, "team", team.id)
    if p:
        before = _policy_response(p)
    else:
        p = Policy(entity_type="team", entity_id=team.id)
        db.add(p)

    p.ip_allowlist   = req.ip_allowlist
    p.allowed_from   = _parse_time(req.allowed_from)
    p.allowed_to     = _parse_time(req.allowed_to)
    p.cn_required    = req.cn_required
    p.rate_limit_rpm = req.rate_limit_rpm
    p.updated_at     = datetime.now(timezone.utc)
    p.updated_by     = session["username"]
    db.commit()
    db.refresh(p)
    after = _policy_response(p)
    _write_change(db, "updated", "team", str(team.id), team.name,
                  "policy updated", session["username"],
                  diff=_compute_diff(before, after))
    return after


@router.delete("/admin/api/teams/{team_id}/policy", status_code=204)
def admin_delete_team_policy(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    p    = _get_policy(db, "team", team.id)
    if p:
        db.delete(p)
        db.commit()
        _write_change(db, "deleted", "team", str(team.id), team.name,
                      "policy removed", session["username"])


def _apply_key_expiry_to_registry(db: Session, registry: Registry, max_key_days: int):
    """Set/update expires_at on all active keys for this registry based on max_key_days."""
    from datetime import timedelta
    for key_row in db.query(TeamRegistryKey).filter(
        TeamRegistryKey.registry_id == registry.id,
        TeamRegistryKey.revoked_at.is_(None),
    ).all():
        key_row.expires_at = key_row.created_at + timedelta(days=max_key_days)
    db.commit()


