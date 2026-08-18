"""
admin_teams.py — Admin teams, members and notification channels.
"""

import uuid
from datetime import (
    datetime,
    timezone,
)
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis import (
    secret_cache,
)
from aegis import (
    webhook as wh,
)
from aegis.database import get_db
from aegis.deps import (
    _generate_key,
    _get_policy,
    _get_registry,
    _get_team,
    _hash_key,
    _require_admin,
    _write_change,
)
from aegis.models import (
    Team,
    TeamRegistry,
    TeamRegistryKey,
    User,
    UserTeam,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Admin API — teams
# ---------------------------------------------------------------------------

def _team_response(team: Team) -> dict:
    # Build a map of registry_id → active key row for this team
    active_keys = {
        str(k.registry_id): k
        for k in team.keys if k.revoked_at is None
    }
    return {
        "id":         str(team.id),
        "name":       team.name,
        "created_at": team.created_at.isoformat() if team.created_at else None,
        "registries": [
            {
                "id":          str(tr.registry_id),
                "name":        tr.registry.name,
                "key_id":      str(active_keys[str(tr.registry_id)].id) if str(tr.registry_id) in active_keys else None,
                "key_preview": active_keys[str(tr.registry_id)].key_preview if str(tr.registry_id) in active_keys else None,
                "key_suspended": active_keys[str(tr.registry_id)].suspended if str(tr.registry_id) in active_keys else False,
                "expires_at":  active_keys[str(tr.registry_id)].expires_at.isoformat() if str(tr.registry_id) in active_keys and active_keys[str(tr.registry_id)].expires_at else None,
                "objects":     [ro.object_name for ro in tr.registry.registry_entries],
            }
            for tr in team.registry_links
        ],
        "members": [
            {"id": str(m.user.id), "username": m.user.username, "role": m.user.role}
            for m in team.members
        ],
        "notifications": {
            "slack_webhook_url":    team.slack_webhook_url,
            "ms_teams_webhook_url": team.ms_teams_webhook_url,
            "discord_webhook_url":  team.discord_webhook_url,
        },
    }


@router.get("/admin/api/teams")
def admin_list_teams(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    teams = db.query(Team).order_by(Team.name).all()
    return [_team_response(t) for t in teams]


class TeamRequest(BaseModel):
    name: str


@router.post("/admin/api/teams", status_code=201)
def admin_create_team(req: TeamRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    if db.query(Team).filter(Team.name == req.name).first():
        raise HTTPException(status_code=400, detail=f"Team '{req.name}' already exists")
    team = Team(name=req.name, created_by=session["username"])
    db.add(team)
    db.commit()
    db.refresh(team)
    _write_change(db, "created", "team", str(team.id), team.name, None, session["username"],
                  diff={"name": {"to": team.name}})
    return _team_response(team)


@router.delete("/admin/api/teams/{team_id}", status_code=204)
def admin_delete_team(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    reg_names = [tr.registry.name for tr in team.registry_links]
    _write_change(db, "deleted", "team", team_id, team.name, None, session["username"],
                  diff={"name": {"from": team.name}, "registries": {"from": reg_names}})
    db.delete(team)
    db.commit()


@router.post("/admin/api/teams/{team_id}/registries/{reg_id}", status_code=201)
def admin_assign_registry(team_id: str, reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    reg  = _get_registry(db, reg_id)
    if db.query(TeamRegistry).filter(TeamRegistry.team_id == team.id, TeamRegistry.registry_id == reg.id).first():
        raise HTTPException(status_code=409, detail="Registry already assigned to team")
    db.add(TeamRegistry(team_id=team.id, registry_id=reg.id, assigned_by=session["username"]))
    db.flush()
    # Issue a unique API key for this team-registry assignment
    plaintext = _generate_key()
    key_preview = plaintext[:10] + "..."
    reg_policy   = _get_policy(db, "registry", reg.id)
    key_expires  = None
    if reg_policy and reg_policy.max_key_days:
        from datetime import timedelta
        key_expires = datetime.now(timezone.utc) + timedelta(days=reg_policy.max_key_days)
    db.add(TeamRegistryKey(
        team_id=team.id, registry_id=reg.id,
        key_hash=_hash_key(plaintext), key_preview=key_preview,
        expires_at=key_expires,
    ))
    db.commit()
    db.refresh(team)
    _write_change(db, "registry_assigned", "team", str(team.id), team.name,
                  None, session["username"],
                  diff={"registries": {"added": reg.name}, "key_preview": {"to": key_preview}})
    # Return key so it can be shown once
    resp = _team_response(team)
    resp["new_key"] = {"registry_id": str(reg.id), "registry_name": reg.name,
                       "key": plaintext, "key_preview": key_preview}
    return resp


@router.post("/admin/api/teams/{team_id}/registries/{reg_id}/rotate-key")
def admin_rotate_assignment_key(team_id: str, reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    reg  = _get_registry(db, reg_id)
    if not db.query(TeamRegistry).filter(TeamRegistry.team_id == team.id, TeamRegistry.registry_id == reg.id).first():
        raise HTTPException(status_code=404, detail="Registry not assigned to team")
    now = datetime.now(timezone.utc)
    old_preview = next((k.key_preview for k in db.query(TeamRegistryKey).filter(
        TeamRegistryKey.team_id == team.id, TeamRegistryKey.registry_id == reg.id,
        TeamRegistryKey.revoked_at.is_(None),
    ).all()), None)
    for k in db.query(TeamRegistryKey).filter(
        TeamRegistryKey.team_id == team.id, TeamRegistryKey.registry_id == reg.id,
        TeamRegistryKey.revoked_at.is_(None),
    ).all():
        k.revoked_at = now
        secret_cache.invalidate(k.key_hash)
    plaintext = _generate_key()
    new_preview = plaintext[:10] + "..."
    db.add(TeamRegistryKey(
        team_id=team.id, registry_id=reg.id,
        key_hash=_hash_key(plaintext), key_preview=new_preview,
    ))
    db.commit()
    _write_change(db, "key_rotated", "team", str(team.id), team.name, None, session["username"],
                  diff={"registry": {"to": reg.name}, "key_preview": {"from": old_preview, "to": new_preview}})
    wh.fire(db, team, "key.rotated",
            registry={"id": str(reg.id), "name": reg.name},
            new_key=plaintext, key_preview=new_preview, reason="manual_rotation")
    return {"team_id": str(team.id), "registry_id": str(reg.id), "key": plaintext, "key_preview": new_preview}


@router.patch("/admin/api/keys/{key_id}/suspend")
def admin_toggle_key_suspend(key_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    """Toggle key suspension on/off. Suspended keys are rejected at /secrets without being revoked."""
    try:
        kid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found") from None
    k = db.get(TeamRegistryKey, kid)
    if not k:
        raise HTTPException(status_code=404, detail="Key not found")
    if k.revoked_at:
        raise HTTPException(status_code=400, detail="Cannot suspend a revoked key")
    k.suspended = not k.suspended
    if k.suspended:
        secret_cache.invalidate(k.key_hash)
    db.commit()
    state = "suspended" if k.suspended else "enabled"
    _write_change(db, "updated", "team", str(k.team_id), k.team.name if k.team else str(k.team_id),
                  None, session["username"],
                  diff={"key_preview": {"value": k.key_preview}, "key_state": {"to": state}})
    return {"key_id": str(k.id), "suspended": k.suspended, "key_preview": k.key_preview}


@router.delete("/admin/api/teams/{team_id}/registries/{reg_id}", status_code=204)
def admin_remove_registry(team_id: str, reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    reg  = _get_registry(db, reg_id)
    tr = db.query(TeamRegistry).filter(TeamRegistry.team_id == team.id, TeamRegistry.registry_id == reg.id).first()
    if not tr:
        raise HTTPException(status_code=404, detail="Registry not assigned to team")
    # Revoke all active keys for this team-registry assignment
    now = datetime.now(timezone.utc)
    for k in db.query(TeamRegistryKey).filter(
        TeamRegistryKey.team_id == team.id,
        TeamRegistryKey.registry_id == reg.id,
        TeamRegistryKey.revoked_at.is_(None),
    ).all():
        k.revoked_at = now
        secret_cache.invalidate(k.key_hash)
    _write_change(db, "registry_unassigned", "team", str(team.id), team.name,
                  None, session["username"],
                  diff={"registries": {"removed": reg.name}})
    db.delete(tr)
    db.commit()
    db.refresh(team)
    wh.fire(db, team, "key.revoked",
            registry={"id": str(reg.id), "name": reg.name},
            reason="registry_unassigned")


# ---------------------------------------------------------------------------
# Admin API — team member management
# ---------------------------------------------------------------------------

@router.get("/admin/api/teams/{team_id}/members")
def admin_list_team_members(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    members = [
        {"id": str(m.user.id), "username": m.user.username, "role": m.user.role, "theme": m.user.theme}
        for m in team.members
    ]
    return {"team_id": str(team.id), "members": members}


class TeamMemberRequest(BaseModel):
    user_id: str


@router.post("/admin/api/teams/{team_id}/members", status_code=201)
def admin_add_team_member(team_id: str, req: TeamMemberRequest,
                          session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    try:
        uid = uuid.UUID(req.user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user_id") from None
    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    existing = db.query(UserTeam).filter(UserTeam.user_id == uid, UserTeam.team_id == team.id).first()
    if existing:
        raise HTTPException(status_code=409, detail="User is already a member of this team")
    db.add(UserTeam(user_id=uid, team_id=team.id))
    db.commit()
    _write_change(db, "updated", "team", str(team.id), team.name,
                  f"added member {user.username}", session["username"])
    return {"ok": True, "user_id": str(uid), "team_id": str(team.id)}


@router.delete("/admin/api/teams/{team_id}/members/{user_id}", status_code=204)
def admin_remove_team_member(team_id: str, user_id: str,
                             session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found") from None
    user = db.query(User).filter(User.id == uid).first()
    row = db.query(UserTeam).filter(UserTeam.user_id == uid, UserTeam.team_id == team.id).first()
    if not row:
        raise HTTPException(status_code=404, detail="User is not a member of this team")
    db.delete(row)
    db.commit()
    uname = user.username if user else str(uid)
    _write_change(db, "updated", "team", str(team.id), team.name,
                  f"removed member {uname}", session["username"])


# ---------------------------------------------------------------------------
# Admin API — team notification channels
# ---------------------------------------------------------------------------

class TeamNotificationsRequest(BaseModel):
    slack_webhook_url:    Optional[str] = None
    ms_teams_webhook_url: Optional[str] = None
    discord_webhook_url:  Optional[str] = None


@router.put("/admin/api/teams/{team_id}/notifications")
def admin_set_team_notifications(team_id: str, req: TeamNotificationsRequest,
                                 session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    team.slack_webhook_url    = req.slack_webhook_url    or None
    team.ms_teams_webhook_url = req.ms_teams_webhook_url or None
    team.discord_webhook_url  = req.discord_webhook_url  or None
    db.commit()
    _write_change(db, "updated", "team", str(team.id), team.name,
                  "notification channels updated", session["username"])
    return {
        "slack_webhook_url":    team.slack_webhook_url,
        "ms_teams_webhook_url": team.ms_teams_webhook_url,
        "discord_webhook_url":  team.discord_webhook_url,
    }


