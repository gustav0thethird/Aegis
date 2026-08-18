"""
admin_users.py — Admin users and auth backends.
"""

import uuid
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

from aegis.broker import load_auth
from aegis.database import get_db
from aegis.deps import (
    _compute_diff,
    _hash_pw,
    _require_admin,
    _write_change,
)
from aegis.models import (
    Team,
    User,
    UserTeam,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Admin API — users
# ---------------------------------------------------------------------------

def _user_response(user: User) -> dict:
    return {
        "id":         str(user.id),
        "username":   user.username,
        "role":       user.role,
        "team_ids":   [str(m.team_id) for m in (user.team_memberships or [])],
        "theme":      user.theme,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "created_by": user.created_by,
    }


@router.get("/admin/api/users")
def admin_list_users(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    return [_user_response(u) for u in db.query(User).order_by(User.username).all()]


class UserCreateRequest(BaseModel):
    username:  str
    password:  str
    role:      str = "user"
    team_ids:  List[str] = []
    theme:     str = "default"


@router.post("/admin/api/users", status_code=201)
def admin_create_user(req: UserCreateRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail=f"Username '{req.username}' already exists")
    if req.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")
    # Validate team IDs
    team_uuids = []
    for tid in req.team_ids:
        try:
            team_uuids.append(uuid.UUID(tid))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid team_id: {tid}") from None
    for tu in team_uuids:
        if not db.query(Team).filter(Team.id == tu).first():
            raise HTTPException(status_code=404, detail=f"Team {tu} not found")
    user = User(
        username=req.username,
        password_hash=_hash_pw(req.password),
        role=req.role,
        theme=req.theme,
        created_by=session["username"],
    )
    db.add(user)
    db.flush()
    for tu in team_uuids:
        db.add(UserTeam(user_id=user.id, team_id=tu))
    db.commit()
    db.refresh(user)
    _write_change(db, "created", "user", str(user.id), user.username,
                  None, session["username"],
                  diff={"role": {"to": user.role},
                        "team_ids": {"to": [str(t) for t in team_uuids]},
                        "theme": {"to": user.theme}})
    return _user_response(user)


class UserUpdateRequest(BaseModel):
    role:     Optional[str]       = None
    team_ids: Optional[List[str]] = None
    theme:    Optional[str]       = None
    password: Optional[str]       = None


@router.put("/admin/api/users/{user_id}")
def admin_update_user(user_id: str, req: UserUpdateRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found") from None
    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    before_team_ids = [str(m.team_id) for m in (user.team_memberships or [])]
    before_snap = {"role": user.role, "team_ids": before_team_ids, "theme": user.theme}
    if req.role is not None:
        if req.role not in ("admin", "user"):
            raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")
        user.role = req.role
    if req.theme is not None:
        user.theme = req.theme
    if req.password is not None:
        user.password_hash = _hash_pw(req.password)
    if req.team_ids is not None:
        # Validate all team IDs first
        team_uuids = []
        for tid in req.team_ids:
            try:
                team_uuids.append(uuid.UUID(tid))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid team_id: {tid}") from None
        for tu in team_uuids:
            if not db.query(Team).filter(Team.id == tu).first():
                raise HTTPException(status_code=404, detail=f"Team {tu} not found")
        # Replace memberships
        db.query(UserTeam).filter(UserTeam.user_id == user.id).delete()
        for tu in team_uuids:
            db.add(UserTeam(user_id=user.id, team_id=tu))
    db.commit()
    db.refresh(user)
    after_team_ids = [str(m.team_id) for m in (user.team_memberships or [])]
    after_snap = {"role": user.role, "team_ids": after_team_ids, "theme": user.theme}
    diff = _compute_diff(before_snap, after_snap)
    if req.password is not None:
        diff["password"] = {"to": "****"}
    _write_change(db, "updated", "user", str(user.id), user.username,
                  None, session["username"], diff=diff if diff else None)
    return _user_response(user)


@router.delete("/admin/api/users/{user_id}", status_code=204)
def admin_delete_user(user_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found") from None
    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete the built-in admin account")
    _write_change(db, "deleted", "user", str(user.id), user.username, None, session["username"],
                  diff={"role": {"from": user.role}, "team_id": {"from": str(user.team_id) if user.team_id else None}})
    db.delete(user)
    db.commit()


# ---------------------------------------------------------------------------
# Auth backend management
# ---------------------------------------------------------------------------

_MASKED_FIELDS = {"token", "api_key", "password", "secret", "auth_object"}

def _mask_auth_cfg(cfg: dict) -> dict:
    return {k: ("••••••••" if k in _MASKED_FIELDS else v) for k, v in cfg.items()}


@router.get("/admin/api/auth-backends")
def admin_auth_backends(session: dict = Depends(_require_admin)):
    """Return the currently loaded auth.json structure (secrets masked)."""
    try:
        raw = load_auth()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Cannot read auth.json: {e}") from e

    result = {}
    for vendor, refs in raw.items():
        result[vendor] = {ref: _mask_auth_cfg(cfg) for ref, cfg in refs.items()}
    return result


@router.post("/admin/api/auth-backends/{vendor}/{ref}/test")
def admin_test_auth_backend(vendor: str, ref: str, session: dict = Depends(_require_admin)):
    """Attempt a basic connectivity check against the backend."""
    import socket
    try:
        raw = load_auth()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Cannot read auth.json: {e}") from e

    cfg = raw.get(vendor, {}).get(ref)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"No config for {vendor}/{ref}")

    # Determine host and port based on vendor
    host = port = None
    if vendor == "vault":
        import urllib.parse
        parsed = urllib.parse.urlparse(cfg.get("addr", ""))
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 8200)
    elif vendor == "cyberark" or vendor == "conjur":
        host = cfg.get("host")
        port = 443
    elif vendor == "aws":
        host = f"secretsmanager.{cfg.get('region', 'us-east-1')}.amazonaws.com"
        port = 443

    if not host:
        return {"reachable": None, "detail": "No host to test for this vendor"}

    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return {"reachable": True, "host": host, "port": port}
    except Exception as e:
        return {"reachable": False, "host": host, "port": port, "error": str(e)}


