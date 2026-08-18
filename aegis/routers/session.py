"""
session.py — Session authentication.
"""

import json
import uuid

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis.database import get_db
from aegis.deps import (
    _create_session,
    _delete_session,
    _extract_bearer_token,
    _get_redis,
    _get_setting_int,
    _require_admin,
    _require_any_user,
    _session_key,
    _verify_pw,
)
from aegis.models import User

router = APIRouter()

# ---------------------------------------------------------------------------
# Session auth endpoints
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/api/login")
def api_login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not _verify_pw(req.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    ttl = _get_setting_int(db, "session_ttl_hours", 8)
    token = _create_session(user, ttl)
    return {
        "token":    token,
        "username": user.username,
        "role":     user.role,
        "team_ids": [str(m.team_id) for m in (user.team_memberships or [])],
        "theme":    user.theme,
    }


@router.post("/api/logout")
def api_logout(request: Request):
    token = _extract_bearer_token(request)
    if token:
        _delete_session(token)
    return {"ok": True}


@router.get("/api/me")
def api_me(session: dict = Depends(_require_any_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == uuid.UUID(session["user_id"])).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user_id":  str(user.id),
        "username": user.username,
        "role":     user.role,
        "team_ids": [str(m.team_id) for m in (user.team_memberships or [])],
        "theme":    user.theme,
    }


class ThemeUpdate(BaseModel):
    theme: str


@router.put("/api/me/theme")
def api_update_theme(req: ThemeUpdate, request: Request, session: dict = Depends(_require_any_user), db: Session = Depends(get_db)):
    valid_themes = {"default", "midnight", "slate", "forest", "contrast"}
    if req.theme not in valid_themes:
        raise HTTPException(status_code=400, detail=f"Invalid theme. Valid: {sorted(valid_themes)}")
    user = db.query(User).filter(User.id == uuid.UUID(session["user_id"])).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.theme = req.theme
    db.commit()
    # Refresh session in Redis
    token = _extract_bearer_token(request)
    if token:
        session["theme"] = req.theme
        r = _get_redis()
        ttl = r.ttl(_session_key(token))
        if ttl > 0:
            r.setex(_session_key(token), ttl, json.dumps(session))
    return {"theme": req.theme}


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

@router.get("/admin/api/sessions")
def admin_list_sessions(session: dict = Depends(_require_admin)):
    """List all active sessions from Redis."""
    r = _get_redis()
    sessions = []
    try:
        for key in r.scan_iter("aegis:session:*"):
            raw = r.get(key)
            if not raw:
                continue
            try:
                data = json.loads(raw)
                token_preview = key.decode().replace("aegis:session:", "")[:12] + "..."
                ttl = r.ttl(key)
                sessions.append({
                    "token_preview": token_preview,
                    "token_key":     key.decode(),   # full Redis key for deletion
                    "username":      data.get("username"),
                    "role":          data.get("role"),
                    "team_id":       data.get("team_id"),
                    "ttl_seconds":   ttl,
                })
            except Exception:
                continue
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis error: {e}") from e
    return {"sessions": sessions, "total": len(sessions)}


@router.delete("/admin/api/sessions/{token_key:path}", status_code=204)
def admin_revoke_session(token_key: str, session: dict = Depends(_require_admin)):
    """Revoke a session by its Redis key. Prefix aegis:session: is expected."""
    if not token_key.startswith("aegis:session:"):
        raise HTTPException(status_code=400, detail="Invalid token key")
    r = _get_redis()
    deleted = r.delete(token_key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found or already expired")


