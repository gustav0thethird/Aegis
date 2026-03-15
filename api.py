"""
api.py — FastAPI service for the Aegis.

Developer endpoint:
  GET  /health
  GET  /secrets      Bearer = registry API key, X-Change-Number header required

Auth:
  POST /api/login    username + password → session token
  POST /api/logout
  GET  /api/me
  PUT  /api/me/theme

User (role=user, read-only own team):
  GET  /api/my-team

Admin UI:
  GET  /admin        Serve the admin HTML panel

Admin API (session token with role=admin OR Basic admin/$ADMIN_PASSWORD):
  GET    /admin/api/ping

  Objects: GET/POST/PUT/DELETE /admin/api/objects[/{name}]

  Registries: GET/POST/DELETE /admin/api/registries[/{id}]
              POST   /admin/api/registries/{id}/objects
              DELETE /admin/api/registries/{id}/objects/{name}

  Teams: GET/POST/DELETE /admin/api/teams[/{id}]
         POST/DELETE /admin/api/teams/{id}/registries/{reg_id}
         POST        /admin/api/teams/{team_id}/registries/{reg_id}/rotate-key

  Users: GET/POST /admin/api/users
         PUT/DELETE /admin/api/users/{id}

  Settings: GET/PUT /admin/api/settings

  Logs: GET /admin/api/changelog
        GET /admin/api/audit
"""

import hashlib
import json
import logging
import os
import secrets as secrets_lib
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Security, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
import bcrypt as _bcrypt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, SessionLocal
from models import AuditLog, ChangeLog, Object, Registry, RegistryObject, Setting, Team, TeamRegistry, TeamRegistryKey, User
from broker import fetch_secrets, load_auth
from siem import build_event, emit, start_s3_flush_thread
import rate_limit

logger = logging.getLogger("aegis")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Aegis", version="2.0.0", docs_url=None, redoc_url=None)
bearer     = HTTPBearer(auto_error=False)
admin_auth = HTTPBasic(auto_error=False)

def _hash_pw(pw: str) -> str:
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()

def _verify_pw(pw: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

# Start S3 flush thread if S3 is configured
_destinations = os.environ.get("LOG_DESTINATIONS", "stdout").lower()
if "s3" in _destinations:
    start_s3_flush_thread()


# ---------------------------------------------------------------------------
# Startup — seed default admin user if none exists
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _seed_admin():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.role == "admin").first():
            admin_pw = os.environ.get("ADMIN_PASSWORD", "changeme")
            db.add(User(
                username="admin",
                password_hash=_hash_pw(admin_pw),
                role="admin",
                theme="default",
                created_by="system",
            ))
            db.commit()
            logger.info("Seeded default admin user")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _generate_key() -> str:
    return "sk_" + secrets_lib.token_urlsafe(32)


def _get_redis():
    return rate_limit._redis_client()


def _session_key(token: str) -> str:
    return f"aegis:session:{token}"


def _create_session(user: User, ttl_hours: int = 8) -> str:
    token = secrets_lib.token_urlsafe(32)
    r = _get_redis()
    payload = json.dumps({
        "user_id": str(user.id),
        "username": user.username,
        "role": user.role,
        "team_id": str(user.team_id) if user.team_id else None,
        "theme": user.theme,
    })
    r.setex(_session_key(token), ttl_hours * 3600, payload)
    return token


def _get_session(token: str) -> Optional[dict]:
    try:
        r = _get_redis()
        raw = r.get(_session_key(token))
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


def _delete_session(token: str):
    try:
        _get_redis().delete(_session_key(token))
    except Exception:
        pass


def _extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


async def _require_admin(request: Request, db: Session = Depends(get_db)) -> dict:
    """Accept either a valid admin session token OR HTTP Basic admin credentials."""
    token = _extract_bearer_token(request)
    if token:
        session = _get_session(token)
        if session and session["role"] == "admin":
            return session

    # Fall back to HTTP Basic (for curl / API access)
    from fastapi.security.utils import get_authorization_scheme_param
    auth_header = request.headers.get("Authorization", "")
    scheme, credentials = get_authorization_scheme_param(auth_header)
    if scheme.lower() == "basic":
        import base64
        try:
            decoded = base64.b64decode(credentials).decode("utf-8")
            username, _, password = decoded.partition(":")
            admin_password = os.environ.get("ADMIN_PASSWORD", "")
            ok = (
                secrets_lib.compare_digest(username.encode(), b"admin") and
                secrets_lib.compare_digest(password.encode(), admin_password.encode())
            )
            if ok:
                return {"username": "admin", "role": "admin", "team_id": None}
        except Exception:
            pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _require_any_user(request: Request) -> dict:
    """Accept any valid session token (admin or user)."""
    token = _extract_bearer_token(request)
    if token:
        session = _get_session(token)
        if session:
            return session
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


# ---------------------------------------------------------------------------
# Developer endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/secrets")
def get_secrets(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer),
    x_change_number: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    api_key    = credentials.credentials
    key_hash   = _hash_key(api_key)
    source_ip  = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # --- Lookup key — now in team_registry_keys for full traceability ---
    key_row = db.query(TeamRegistryKey).filter(
        TeamRegistryKey.key_hash == key_hash,
        TeamRegistryKey.revoked_at.is_(None),
    ).first()

    if not key_row:
        logger.warning("Rejected unknown/revoked key (hash prefix: %s...)", key_hash[:8])
        _write_audit(db, "auth.failed", "denied",
                     key_preview=api_key[:10] + "...",
                     source_ip=source_ip, user_agent=user_agent,
                     error_detail="Unknown or revoked API key")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    registry    = key_row.registry
    team        = key_row.team
    key_preview = key_row.key_preview

    # --- Ticket enforcement ---
    cn_required = _get_setting_bool(db, "change_number_required", True)
    if cn_required and not x_change_number:
        logger.warning("Blocked registry=%s team=%s: missing X-Change-Number", registry.name, team.name)
        _write_audit(db, "secrets.blocked", "denied",
                     registry_id=str(registry.id), registry_name=registry.name,
                     team_id=str(team.id), team_name=team.name,
                     objects=[ro.object_name for ro in registry.registry_entries],
                     key_preview=key_preview, source_ip=source_ip, user_agent=user_agent,
                     error_detail="Missing X-Change-Number header")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="X-Change-Number header is required")

    # --- Rate limiting (per key ID) ---
    rpm = _get_setting_int(db, "rate_limit_rpm", 60)
    allowed, remaining = rate_limit.check(str(key_row.id), rpm)
    if not allowed:
        _write_audit(db, "secrets.blocked", "denied",
                     change_number=x_change_number,
                     registry_id=str(registry.id), registry_name=registry.name,
                     team_id=str(team.id), team_name=team.name,
                     objects=[ro.object_name for ro in registry.registry_entries],
                     key_preview=key_preview, source_ip=source_ip, user_agent=user_agent,
                     error_detail="Rate limit exceeded")
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    # --- Fetch secrets ---
    object_rows = [
        {"name": ro.object.name, "vendor": ro.object.vendor, "auth_ref": ro.object.auth_ref,
         "path": ro.object.path, "platform": ro.object.platform, "safe": ro.object.safe}
        for ro in registry.registry_entries
    ]
    object_names = [o["name"] for o in object_rows]
    logger.info("Request team=%s registry=%s change=%s objects=%s",
                team.name, registry.name, x_change_number, object_names)

    try:
        auth    = load_auth()
        fetched = fetch_secrets(object_rows, auth)
    except Exception as exc:
        logger.error("Fetch failed team=%s registry=%s: %s", team.name, registry.name, exc)
        _write_audit(db, "secrets.fetched", "error",
                     change_number=x_change_number,
                     registry_id=str(registry.id), registry_name=registry.name,
                     team_id=str(team.id), team_name=team.name,
                     objects=object_names, key_preview=key_preview,
                     source_ip=source_ip, user_agent=user_agent, error_detail=str(exc))
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    _write_audit(db, "secrets.fetched", "success",
                 change_number=x_change_number,
                 registry_id=str(registry.id), registry_name=registry.name,
                 team_id=str(team.id), team_name=team.name,
                 objects=object_names, key_preview=key_preview,
                 source_ip=source_ip, user_agent=user_agent)
    return fetched


# ---------------------------------------------------------------------------
# Session auth endpoints
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
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
        "team_id":  str(user.team_id) if user.team_id else None,
        "theme":    user.theme,
    }


@app.post("/api/logout")
def api_logout(request: Request):
    token = _extract_bearer_token(request)
    if token:
        _delete_session(token)
    return {"ok": True}


@app.get("/api/me")
def api_me(session: dict = Depends(_require_any_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == uuid.UUID(session["user_id"])).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user_id":  str(user.id),
        "username": user.username,
        "role":     user.role,
        "team_id":  str(user.team_id) if user.team_id else None,
        "theme":    user.theme,
    }


class ThemeUpdate(BaseModel):
    theme: str


@app.put("/api/me/theme")
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
# User role — read-only team view
# ---------------------------------------------------------------------------

@app.get("/api/my-team")
def api_my_team(session: dict = Depends(_require_any_user), db: Session = Depends(get_db)):
    if session["role"] == "admin":
        raise HTTPException(status_code=400, detail="Admins use the admin API")
    team_id = session.get("team_id")
    if not team_id:
        return {"team": None, "registries": [], "objects": []}
    team = db.query(Team).filter(Team.id == uuid.UUID(team_id)).first()
    if not team:
        return {"team": None, "registries": [], "objects": []}

    registries = []
    all_objects = {}
    for tr in team.registry_links:
        reg = tr.registry
        reg_objects = [ro.object_name for ro in reg.registry_entries]
        registries.append({"id": str(reg.id), "name": reg.name, "objects": reg_objects})
        for ro in reg.registry_entries:
            obj = ro.object
            all_objects[obj.name] = {
                "name": obj.name, "vendor": obj.vendor,
                "path": obj.path, "platform": obj.platform, "safe": obj.safe,
            }

    return {
        "team": {"id": str(team.id), "name": team.name},
        "registries": registries,
        "objects": list(all_objects.values()),
    }


# ---------------------------------------------------------------------------
# Admin UI
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/admin", include_in_schema=False)
def admin_ui():
    return FileResponse("static/index.html")


# ---------------------------------------------------------------------------
# Admin API — ping
# ---------------------------------------------------------------------------

@app.get("/admin/api/ping")
def admin_ping(session: dict = Depends(_require_admin)):
    return {"ok": True, "role": session["role"]}


# ---------------------------------------------------------------------------
# Admin API — objects
# ---------------------------------------------------------------------------

class ObjectRequest(BaseModel):
    name:     str
    vendor:   str
    auth_ref: str
    path:     str
    platform: Optional[str] = None
    safe:     Optional[str] = None


def _obj_response(obj: Object) -> dict:
    return {
        "name":     obj.name,
        "vendor":   obj.vendor,
        "auth_ref": obj.auth_ref,
        "path":     obj.path,
        "platform": obj.platform,
        "safe":     obj.safe,
        "created_at": obj.created_at.isoformat() if obj.created_at else None,
    }


@app.get("/admin/api/objects")
def admin_list_objects(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    objects = db.query(Object).order_by(Object.name).all()
    result = []
    for obj in objects:
        d = _obj_response(obj)
        d["registry_count"] = len(obj.registry_entries)
        result.append(d)
    return result


@app.post("/admin/api/objects", status_code=201)
def admin_create_object(req: ObjectRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    if db.query(Object).filter(Object.name == req.name).first():
        raise HTTPException(status_code=400, detail=f"Object '{req.name}' already exists")
    obj = Object(name=req.name, vendor=req.vendor, auth_ref=req.auth_ref,
                 path=req.path, platform=req.platform, safe=req.safe,
                 created_by=session["username"])
    db.add(obj)
    db.commit()
    db.refresh(obj)
    _write_change(db, "created", "object", obj.name, obj.name,
                  None, session["username"],
                  diff={"vendor": {"to": obj.vendor}, "auth_ref": {"to": obj.auth_ref},
                        "path": {"to": obj.path}, "platform": {"to": obj.platform},
                        "safe": {"to": obj.safe}})
    d = _obj_response(obj)
    d["registry_count"] = 0
    return d


class ObjectUpdateRequest(BaseModel):
    vendor:   str
    auth_ref: str
    path:     str
    platform: Optional[str] = None
    safe:     Optional[str] = None


@app.put("/admin/api/objects/{name}")
def admin_update_object(name: str, req: ObjectUpdateRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    obj = db.query(Object).filter(Object.name == name).first()
    if not obj:
        raise HTTPException(status_code=404, detail=f"Object '{name}' not found")
    before = _obj_snapshot(obj)
    obj.vendor = req.vendor; obj.auth_ref = req.auth_ref
    obj.path   = req.path;   obj.platform = req.platform; obj.safe = req.safe
    db.commit()
    db.refresh(obj)
    after = _obj_snapshot(obj)
    _write_change(db, "updated", "object", name, name,
                  None, session["username"], diff=_compute_diff(before, after))
    d = _obj_response(obj)
    d["registry_count"] = len(obj.registry_entries)
    return d


@app.delete("/admin/api/objects/{name}", status_code=204)
def admin_delete_object(name: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    obj = db.query(Object).filter(Object.name == name).first()
    if not obj:
        raise HTTPException(status_code=404, detail=f"Object '{name}' not found")
    if obj.registry_entries:
        raise HTTPException(status_code=409, detail=f"Object '{name}' is used by {len(obj.registry_entries)} registry/registries")
    snap = _obj_snapshot(obj)
    _write_change(db, "deleted", "object", name, name, None, session["username"],
                  diff={"vendor": {"from": snap["vendor"]}, "path": {"from": snap["path"]}})
    db.delete(obj)
    db.commit()


# ---------------------------------------------------------------------------
# Admin API — registries
# ---------------------------------------------------------------------------

def _reg_response(reg: Registry) -> dict:
    return {
        "id":         str(reg.id),
        "name":       reg.name,
        "created_at": reg.created_at.isoformat() if reg.created_at else None,
        "objects":    [ro.object_name for ro in reg.registry_entries],
        "team_count": len(reg.team_links),
    }


@app.get("/admin/api/registries")
def admin_list_registries(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    regs = db.query(Registry).order_by(Registry.name).all()
    return [_reg_response(r) for r in regs]


class RegistryRequest(BaseModel):
    name: str


@app.post("/admin/api/registries", status_code=201)
def admin_create_registry(req: RegistryRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    if db.query(Registry).filter(Registry.name == req.name).first():
        raise HTTPException(status_code=400, detail=f"Registry '{req.name}' already exists")
    reg = Registry(name=req.name, created_by=session["username"])
    db.add(reg)
    db.commit()
    db.refresh(reg)
    _write_change(db, "created", "registry", str(reg.id), reg.name, None, session["username"],
                  diff={"name": {"to": reg.name}})
    return _reg_response(reg)


@app.delete("/admin/api/registries/{reg_id}", status_code=204)
def admin_delete_registry(reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    if reg.team_links:
        raise HTTPException(status_code=409, detail=f"Registry is assigned to {len(reg.team_links)} team(s)")
    obj_names = [ro.object_name for ro in reg.registry_entries]
    _write_change(db, "deleted", "registry", reg_id, reg.name, None, session["username"],
                  diff={"name": {"from": reg.name}, "objects": {"from": obj_names}})
    db.delete(reg)
    db.commit()


class AddObjectRequest(BaseModel):
    object_name: str


@app.post("/admin/api/registries/{reg_id}/objects", status_code=201)
def admin_add_object_to_registry(reg_id: str, req: AddObjectRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    obj = db.query(Object).filter(Object.name == req.object_name).first()
    if not obj:
        raise HTTPException(status_code=404, detail=f"Object '{req.object_name}' not found")
    if db.query(RegistryObject).filter(RegistryObject.registry_id == reg.id, RegistryObject.object_name == req.object_name).first():
        raise HTTPException(status_code=409, detail="Object already in registry")
    db.add(RegistryObject(registry_id=reg.id, object_name=req.object_name))
    db.commit()
    db.refresh(reg)
    _write_change(db, "object_added", "registry", str(reg.id), reg.name,
                  None, session["username"],
                  diff={"objects": {"added": req.object_name}})
    return _reg_response(reg)


@app.delete("/admin/api/registries/{reg_id}/objects/{object_name}", status_code=204)
def admin_remove_object_from_registry(reg_id: str, object_name: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    ro = db.query(RegistryObject).filter(RegistryObject.registry_id == reg.id, RegistryObject.object_name == object_name).first()
    if not ro:
        raise HTTPException(status_code=404, detail=f"Object '{object_name}' not in registry")
    db.delete(ro)
    db.commit()
    _write_change(db, "object_removed", "registry", str(reg.id), reg.name,
                  None, session["username"],
                  diff={"objects": {"removed": object_name}})




# ---------------------------------------------------------------------------
# Admin API — teams
# ---------------------------------------------------------------------------

def _team_response(team: Team) -> dict:
    # Build a map of registry_id → active key_preview for this team
    active_keys = {
        str(k.registry_id): k.key_preview
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
                "key_preview": active_keys.get(str(tr.registry_id)),
                "objects":     [ro.object_name for ro in tr.registry.registry_entries],
            }
            for tr in team.registry_links
        ],
    }


@app.get("/admin/api/teams")
def admin_list_teams(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    teams = db.query(Team).order_by(Team.name).all()
    return [_team_response(t) for t in teams]


class TeamRequest(BaseModel):
    name: str


@app.post("/admin/api/teams", status_code=201)
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


@app.delete("/admin/api/teams/{team_id}", status_code=204)
def admin_delete_team(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    reg_names = [tr.registry.name for tr in team.registry_links]
    _write_change(db, "deleted", "team", team_id, team.name, None, session["username"],
                  diff={"name": {"from": team.name}, "registries": {"from": reg_names}})
    db.delete(team)
    db.commit()


@app.post("/admin/api/teams/{team_id}/registries/{reg_id}", status_code=201)
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
    db.add(TeamRegistryKey(
        team_id=team.id, registry_id=reg.id,
        key_hash=_hash_key(plaintext), key_preview=key_preview,
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


@app.post("/admin/api/teams/{team_id}/registries/{reg_id}/rotate-key")
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
    plaintext = _generate_key()
    new_preview = plaintext[:10] + "..."
    db.add(TeamRegistryKey(
        team_id=team.id, registry_id=reg.id,
        key_hash=_hash_key(plaintext), key_preview=new_preview,
    ))
    db.commit()
    _write_change(db, "key_rotated", "team", str(team.id), team.name, None, session["username"],
                  diff={"registry": {"to": reg.name}, "key_preview": {"from": old_preview, "to": new_preview}})
    return {"team_id": str(team.id), "registry_id": str(reg.id), "key": plaintext, "key_preview": new_preview}


@app.delete("/admin/api/teams/{team_id}/registries/{reg_id}", status_code=204)
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
    _write_change(db, "registry_unassigned", "team", str(team.id), team.name,
                  None, session["username"],
                  diff={"registries": {"removed": reg.name}})
    db.delete(tr)
    db.commit()


# ---------------------------------------------------------------------------
# Admin API — users
# ---------------------------------------------------------------------------

def _user_response(user: User) -> dict:
    return {
        "id":         str(user.id),
        "username":   user.username,
        "role":       user.role,
        "team_id":    str(user.team_id) if user.team_id else None,
        "theme":      user.theme,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "created_by": user.created_by,
    }


@app.get("/admin/api/users")
def admin_list_users(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    return [_user_response(u) for u in db.query(User).order_by(User.username).all()]


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role:     str = "user"
    team_id:  Optional[str] = None
    theme:    str = "default"


@app.post("/admin/api/users", status_code=201)
def admin_create_user(req: UserCreateRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail=f"Username '{req.username}' already exists")
    if req.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")
    team_uuid = None
    if req.team_id:
        try:
            team_uuid = uuid.UUID(req.team_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid team_id")
        if not db.query(Team).filter(Team.id == team_uuid).first():
            raise HTTPException(status_code=404, detail="Team not found")
    user = User(
        username=req.username,
        password_hash=_hash_pw(req.password),
        role=req.role,
        team_id=team_uuid,
        theme=req.theme,
        created_by=session["username"],
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _write_change(db, "created", "user", str(user.id), user.username,
                  None, session["username"],
                  diff={"role": {"to": user.role}, "team_id": {"to": str(user.team_id) if user.team_id else None},
                        "theme": {"to": user.theme}})
    return _user_response(user)


class UserUpdateRequest(BaseModel):
    role:     Optional[str] = None
    team_id:  Optional[str] = None
    theme:    Optional[str] = None
    password: Optional[str] = None


@app.put("/admin/api/users/{user_id}")
def admin_update_user(user_id: str, req: UserUpdateRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    before_snap = {"role": user.role, "team_id": str(user.team_id) if user.team_id else None, "theme": user.theme}
    if req.role is not None:
        if req.role not in ("admin", "user"):
            raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")
        user.role = req.role
    if req.theme is not None:
        user.theme = req.theme
    if req.password is not None:
        user.password_hash = _hash_pw(req.password)
    if "team_id" in req.model_fields_set:
        if req.team_id:
            try:
                team_uuid = uuid.UUID(req.team_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid team_id")
            if not db.query(Team).filter(Team.id == team_uuid).first():
                raise HTTPException(status_code=404, detail="Team not found")
            user.team_id = team_uuid
        else:
            user.team_id = None
    db.commit()
    db.refresh(user)
    after_snap = {"role": user.role, "team_id": str(user.team_id) if user.team_id else None, "theme": user.theme}
    diff = _compute_diff(before_snap, after_snap)
    if req.password is not None:
        diff["password"] = {"to": "****"}
    _write_change(db, "updated", "user", str(user.id), user.username,
                  None, session["username"], diff=diff if diff else None)
    return _user_response(user)


@app.delete("/admin/api/users/{user_id}", status_code=204)
def admin_delete_user(user_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
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
# Admin API — settings
# ---------------------------------------------------------------------------

EDITABLE_SETTINGS = {
    "siem_destinations", "splunk_hec_url", "splunk_hec_token",
    "s3_log_bucket", "dd_api_key", "rate_limit_rpm",
    "change_number_required", "session_ttl_hours", "log_retention_days",
}


@app.get("/admin/api/settings")
def admin_get_settings(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    rows = db.query(Setting).all()
    return {r.key: r.value for r in rows}


class SettingsPatch(BaseModel):
    settings: dict


@app.put("/admin/api/settings")
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
# Admin API — change log
# ---------------------------------------------------------------------------

@app.get("/admin/api/changelog")
def admin_changelog(
    session: dict = Depends(_require_admin),
    page: int = 1, limit: int = 50,
    entity_type: Optional[str] = None,
    entity_id:   Optional[str] = None,
    action:      Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(ChangeLog).order_by(ChangeLog.timestamp.desc())
    if entity_type: q = q.filter(ChangeLog.entity_type == entity_type)
    if entity_id:   q = q.filter(ChangeLog.entity_id   == entity_id)
    if action:      q = q.filter(ChangeLog.action       == action)
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

@app.get("/admin/api/audit")
def admin_audit_log(
    session: dict = Depends(_require_admin),
    page: int = 1, limit: int = 50,
    registry_id:   Optional[str] = None,
    change_number: Optional[str] = None,
    outcome:       Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    if registry_id:    q = q.filter(AuditLog.registry_id == registry_id)
    if change_number:  q = q.filter(AuditLog.change_number == change_number)
    if outcome:        q = q.filter(AuditLog.outcome == outcome)
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
# Shared helpers
# ---------------------------------------------------------------------------

def _write_change(db: Session, action: str, entity_type: str, entity_id: str,
                  entity_name: str, detail: str = None, performed_by: str = "admin",
                  diff: dict = None):
    db.add(ChangeLog(action=action, entity_type=entity_type, entity_id=entity_id,
                     entity_name=entity_name, detail=detail, performed_by=performed_by,
                     diff=diff))
    db.commit()


def _obj_snapshot(obj: Object) -> dict:
    return {"vendor": obj.vendor, "auth_ref": obj.auth_ref, "path": obj.path,
            "platform": obj.platform, "safe": obj.safe}


def _compute_diff(before: dict, after: dict) -> dict:
    """Return only fields that changed, with from/to values."""
    return {k: {"from": before.get(k), "to": after.get(k)}
            for k in set(before) | set(after) if before.get(k) != after.get(k)}


def _build_siem_config(db: Session) -> dict:
    """Read SIEM runtime config from DB settings (fallback to env)."""
    keys = ["siem_destinations", "splunk_hec_url", "splunk_hec_token",
            "s3_log_bucket", "s3_log_prefix", "dd_api_key", "dd_site"]
    cfg = {}
    for k in keys:
        row = db.query(Setting).filter(Setting.key == k).first()
        if row and row.value:
            # normalise key: siem_destinations → destinations for siem.emit()
            out_key = k[5:] if k.startswith("siem_") else k
            cfg[out_key] = row.value
    return cfg


def _write_audit(db: Session, event: str, outcome: str, **kwargs):
    db.add(AuditLog(event=event, outcome=outcome, **kwargs))
    db.commit()
    siem_event = build_event(event, outcome, **kwargs)
    emit(siem_event, config=_build_siem_config(db))


def _get_setting(db: Session, key: str, default: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row and row.value is not None else default


def _get_setting_int(db: Session, key: str, default: int) -> int:
    try:
        return int(_get_setting(db, key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_setting_bool(db: Session, key: str, default: bool) -> bool:
    val = _get_setting(db, key, str(default)).lower()
    return val in ("true", "1", "yes")


def _get_registry(db: Session, reg_id: str) -> Registry:
    try:
        uid = uuid.UUID(reg_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Registry not found")
    reg = db.query(Registry).filter(Registry.id == uid).first()
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    return reg


def _get_team(db: Session, team_id: str) -> Team:
    try:
        uid = uuid.UUID(team_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Team not found")
    team = db.query(Team).filter(Team.id == uid).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    return team
