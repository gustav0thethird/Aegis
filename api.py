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

User (role=user, self-service):
  GET  /api/my-teams   (plural; /api/my-team kept as backward-compat alias)
  GET  /api/my-webhook           — view webhook + notification channels
  PUT  /api/my-webhook           — configure outgoing webhook + notifications
  DELETE /api/my-webhook         — remove webhook
  GET  /api/my-metrics           — team-scoped audit counts + key stats
  GET  /api/my-metrics/prometheus — team-scoped Prometheus metrics (for Grafana)
  POST /api/inbound/{team_id}    — inbound webhook receiver (CI/CD trigger); Bearer = signing secret

UI:
  GET  /             → redirect to /login
  GET  /login        Standalone login page (redirects to /admin or /dashboard on success)
  GET  /admin        Admin panel (role=admin)
  GET  /dashboard    Team dashboard (role=user)
  GET  /docs         API documentation + companion tester

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

import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import secrets as secrets_lib
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Security, status
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
import bcrypt as _bcrypt
from pydantic import BaseModel
from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from database import get_db, SessionLocal
from models import AuditLog, ChangeLog, Object, Policy, Registry, RegistryObject, Setting, Team, TeamRegistry, TeamRegistryKey, User, UserTeam, Webhook, WebhookLog
from broker import fetch_secrets, load_auth
from siem import build_event, emit, start_s3_flush_thread
import rate_limit
import webhook as wh
import scheduler

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
    team_ids = [str(m.team_id) for m in (user.team_memberships or [])]
    payload = json.dumps({
        "user_id":  str(user.id),
        "username": user.username,
        "role":     user.role,
        "team_ids": team_ids,
        "theme":    user.theme,
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
def health(db: Session = Depends(get_db)):
    details: dict = {}
    ok = True
    # Check DB
    try:
        db.execute(sa_text("SELECT 1"))
        details["db"] = "ok"
    except Exception as e:
        details["db"] = str(e); ok = False
    # Check Redis
    try:
        _get_redis().ping()
        details["redis"] = "ok"
    except Exception as e:
        details["redis"] = str(e); ok = False
    status_code = 200 if ok else 503
    from fastapi.responses import JSONResponse
    return JSONResponse({"status": "ok" if ok else "degraded", **details}, status_code=status_code)


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

    if key_row.suspended:
        logger.warning("Rejected suspended key (hash prefix: %s...)", key_hash[:8])
        _write_audit(db, "auth.failed", "denied",
                     registry_id=str(key_row.registry_id), registry_name=key_row.registry.name,
                     team_id=str(key_row.team_id), team_name=key_row.team.name,
                     key_preview=key_row.key_preview, source_ip=source_ip, user_agent=user_agent,
                     error_detail="Key is suspended")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    registry    = key_row.registry
    team        = key_row.team
    key_preview = key_row.key_preview

    # --- Policy enforcement (team + registry) ---
    _base_audit = dict(
        registry_id=str(registry.id), registry_name=registry.name,
        team_id=str(team.id), team_name=team.name,
        objects=[ro.object_name for ro in registry.registry_entries],
        key_preview=key_preview, source_ip=source_ip, user_agent=user_agent,
        change_number=x_change_number,
    )
    _enforce_policies(db, team, registry, source_ip, x_change_number, _base_audit)

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
        "team_ids": [str(m.team_id) for m in (user.team_memberships or [])],
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
        "team_ids": [str(m.team_id) for m in (user.team_memberships or [])],
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


@app.get("/api/my-teams")
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


@app.get("/api/my-team")
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

def _resolve_user_team(session: dict, db: Session, team_id: Optional[str] = None) -> Team:
    """Return a Team the current user belongs to. team_id selects among multiple; defaults to first."""
    team_ids = session.get("team_ids") or []
    if not team_ids and session.get("team_id"):
        team_ids = [session["team_id"]]
    if not team_ids:
        raise HTTPException(status_code=404, detail="No team assigned")
    if team_id:
        if team_id not in team_ids:
            raise HTTPException(status_code=403, detail="Not a member of that team")
        tid = uuid.UUID(team_id)
    else:
        tid = uuid.UUID(team_ids[0])
    team = db.get(Team, tid)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    return team


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


@app.get("/api/my-webhook")
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


@app.put("/api/my-webhook")
def api_put_my_webhook(
    req: TeamWebhookRequest,
    team_id: Optional[str] = None,
    session: dict = Depends(_require_any_user),
    db: Session = Depends(get_db),
):
    """Create or update webhook config + notification channels for user's team."""
    team = _resolve_user_team(session, db, team_id)

    # Update notification channels on Team
    team.slack_webhook_url    = req.slack_webhook_url
    team.ms_teams_webhook_url = req.ms_teams_webhook_url
    team.discord_webhook_url  = req.discord_webhook_url

    # Upsert HTTP webhook if URL provided
    if req.url:
        from webhook import ALL_EVENTS
        bad = [e for e in req.events if e not in ALL_EVENTS]
        if bad:
            raise HTTPException(status_code=400, detail=f"Unknown events: {bad}")

        wh = team.webhook
        if wh:
            wh.url             = req.url
            wh.enabled         = req.enabled
            wh.events          = req.events
            wh.signing_enabled = req.signing_enabled
            if req.secret is not None:
                wh.secret = req.secret or secrets_lib.token_hex(32)
        else:
            wh = Webhook(
                team_id         = team.id,
                url             = req.url,
                enabled         = req.enabled,
                events          = req.events,
                signing_enabled = req.signing_enabled,
                secret          = req.secret or (secrets_lib.token_hex(32) if req.signing_enabled else None),
                created_by      = session["username"],
            )
            db.add(wh)

    db.commit()
    return {"ok": True}


@app.delete("/api/my-webhook", status_code=204)
def api_delete_my_webhook(
    team_id: Optional[str] = None,
    session: dict = Depends(_require_any_user),
    db: Session = Depends(get_db),
):
    team = _resolve_user_team(session, db, team_id)
    if team.webhook:
        db.delete(team.webhook)
        db.commit()


@app.get("/api/my-metrics")
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


@app.post("/api/inbound/{team_id_str}")
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
    try:
        tid = uuid.UUID(team_id_str)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")

    team = db.get(Team, tid)
    if not team:
        raise HTTPException(status_code=404, detail="Not found")

    # Authenticate with the team's webhook signing secret
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = auth_header[7:]

    wh = team.webhook
    if not wh or not wh.secret or not wh.signing_enabled:
        raise HTTPException(status_code=403, detail="Inbound webhook not configured (enable signing and set secret)")

    import hmac as _hmac
    if not _hmac.compare_digest(token, wh.secret):
        raise HTTPException(status_code=403, detail="Invalid token")

    if req.action == "ping":
        return {"ok": True, "team": team.name, "message": "pong"}

    if req.action == "rotate_key":
        if not req.registry_id:
            raise HTTPException(status_code=400, detail="registry_id required for rotate_key")
        # Delegate to the existing rotation logic
        try:
            reg_uuid = uuid.UUID(req.registry_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid registry_id")
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

        # Rotate key
        new_raw    = secrets_lib.token_urlsafe(40)
        new_hash   = hashlib.sha256(new_raw.encode()).hexdigest()
        new_preview = new_raw[:10]

        old_keys = db.query(TeamRegistryKey).filter(
            TeamRegistryKey.team_id    == tid,
            TeamRegistryKey.registry_id == reg_uuid,
            TeamRegistryKey.revoked_at == None,  # noqa: E711
        ).all()
        for k in old_keys:
            k.revoked_at = datetime.now(timezone.utc)

        new_key = TeamRegistryKey(
            team_id=tid, registry_id=reg_uuid,
            key_hash=new_hash, key_preview=new_preview,
        )
        db.add(new_key)
        db.commit()
        logger.info("Inbound webhook rotated key team=%s registry=%s", tid, reg_uuid)
        return {"ok": True, "key_preview": new_preview, "new_key": new_raw}

    raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")


# ---------------------------------------------------------------------------
# Admin UI
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", include_in_schema=False)
def login_ui():
    return FileResponse("static/login.html")


@app.get("/admin", include_in_schema=False)
def admin_ui():
    return FileResponse("static/index.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_ui():
    return FileResponse("static/dashboard.html")


@app.get("/docs", include_in_schema=False)
def docs_ui():
    return FileResponse("static/docs.html")


# ---------------------------------------------------------------------------
# 404 / error handlers
# ---------------------------------------------------------------------------

from fastapi import Request as _Request
from fastapi.responses import JSONResponse as _JSONResponse
from starlette.exceptions import HTTPException as _StarletteHTTPException


@app.exception_handler(_StarletteHTTPException)
async def http_exception_handler(request: _Request, exc: _StarletteHTTPException):
    # API paths return JSON
    if request.url.path.startswith("/api/") or request.url.path.startswith("/admin/api/") or request.url.path == "/health" or request.url.path == "/secrets" or request.url.path == "/metrics":
        return _JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    # UI paths return the 404 page for 404s, JSON for everything else
    if exc.status_code == 404:
        return FileResponse("static/404.html", status_code=404)
    return _JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


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
    wh.fire(db, team, "key.rotated",
            registry={"id": str(reg.id), "name": reg.name},
            new_key=plaintext, key_preview=new_preview, reason="manual_rotation")
    return {"team_id": str(team.id), "registry_id": str(reg.id), "key": plaintext, "key_preview": new_preview}


@app.patch("/admin/api/keys/{key_id}/suspend")
def admin_toggle_key_suspend(key_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    """Toggle key suspension on/off. Suspended keys are rejected at /secrets without being revoked."""
    try:
        kid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")
    k = db.get(TeamRegistryKey, kid)
    if not k:
        raise HTTPException(status_code=404, detail="Key not found")
    if k.revoked_at:
        raise HTTPException(status_code=400, detail="Cannot suspend a revoked key")
    k.suspended = not k.suspended
    db.commit()
    state = "suspended" if k.suspended else "enabled"
    _write_change(db, "updated", "team", str(k.team_id), k.team.name if k.team else str(k.team_id),
                  None, session["username"],
                  diff={"key_preview": {"value": k.key_preview}, "key_state": {"to": state}})
    return {"key_id": str(k.id), "suspended": k.suspended, "key_preview": k.key_preview}


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
    db.refresh(team)
    wh.fire(db, team, "key.revoked",
            registry={"id": str(reg.id), "name": reg.name},
            reason="registry_unassigned")


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


@app.get("/admin/api/users")
def admin_list_users(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    return [_user_response(u) for u in db.query(User).order_by(User.username).all()]


class UserCreateRequest(BaseModel):
    username:  str
    password:  str
    role:      str = "user"
    team_ids:  List[str] = []
    theme:     str = "default"


@app.post("/admin/api/users", status_code=201)
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
            raise HTTPException(status_code=400, detail=f"Invalid team_id: {tid}")
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


@app.put("/admin/api/users/{user_id}")
def admin_update_user(user_id: str, req: UserUpdateRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
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
                raise HTTPException(status_code=400, detail=f"Invalid team_id: {tid}")
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
# Admin API — team member management
# ---------------------------------------------------------------------------

@app.get("/admin/api/teams/{team_id}/members")
def admin_list_team_members(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    members = [
        {"id": str(m.user.id), "username": m.user.username, "role": m.user.role, "theme": m.user.theme}
        for m in team.members
    ]
    return {"team_id": str(team.id), "members": members}


class TeamMemberRequest(BaseModel):
    user_id: str


@app.post("/admin/api/teams/{team_id}/members", status_code=201)
def admin_add_team_member(team_id: str, req: TeamMemberRequest,
                          session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    try:
        uid = uuid.UUID(req.user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user_id")
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


@app.delete("/admin/api/teams/{team_id}/members/{user_id}", status_code=204)
def admin_remove_team_member(team_id: str, user_id: str,
                             session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
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


@app.put("/admin/api/teams/{team_id}/notifications")
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
# CSV exports
# ---------------------------------------------------------------------------

@app.get("/admin/api/audit/export")
def admin_audit_export(
    outcome:       Optional[str] = None,
    change_number: Optional[str] = None,
    registry_id:   Optional[str] = None,
    session: dict = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    if outcome:        q = q.filter(AuditLog.outcome == outcome)
    if change_number:  q = q.filter(AuditLog.change_number == change_number)
    if registry_id:    q = q.filter(AuditLog.registry_id == registry_id)
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


@app.get("/admin/api/changelog/export")
def admin_changelog_export(
    entity_type: Optional[str] = None,
    action:      Optional[str] = None,
    session: dict = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(ChangeLog).order_by(ChangeLog.timestamp.desc())
    if entity_type: q = q.filter(ChangeLog.entity_type == entity_type)
    if action:      q = q.filter(ChangeLog.action == action)
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


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

@app.get("/admin/api/sessions")
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
        raise HTTPException(status_code=503, detail=f"Redis error: {e}")
    return {"sessions": sessions, "total": len(sessions)}


@app.delete("/admin/api/sessions/{token_key:path}", status_code=204)
def admin_revoke_session(token_key: str, session: dict = Depends(_require_admin)):
    """Revoke a session by its Redis key. Prefix aegis:session: is expected."""
    if not token_key.startswith("aegis:session:"):
        raise HTTPException(status_code=400, detail="Invalid token key")
    r = _get_redis()
    deleted = r.delete(token_key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found or already expired")


# ---------------------------------------------------------------------------
# Auth backend management
# ---------------------------------------------------------------------------

_MASKED_FIELDS = {"token", "api_key", "password", "secret", "auth_object"}

def _mask_auth_cfg(cfg: dict) -> dict:
    return {k: ("••••••••" if k in _MASKED_FIELDS else v) for k, v in cfg.items()}


@app.get("/admin/api/auth-backends")
def admin_auth_backends(session: dict = Depends(_require_admin)):
    """Return the currently loaded auth.json structure (secrets masked)."""
    try:
        import broker
        raw = broker.load_auth()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Cannot read auth.json: {e}")

    result = {}
    for vendor, refs in raw.items():
        result[vendor] = {ref: _mask_auth_cfg(cfg) for ref, cfg in refs.items()}
    return result


@app.post("/admin/api/auth-backends/{vendor}/{ref}/test")
def admin_test_auth_backend(vendor: str, ref: str, session: dict = Depends(_require_admin)):
    """Attempt a basic connectivity check against the backend."""
    import socket
    import broker
    try:
        raw = broker.load_auth()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Cannot read auth.json: {e}")

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
    elif vendor == "cyberark":
        host = cfg.get("host")
        port = 443
    elif vendor == "conjur":
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


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

@app.get("/api/my-metrics/prometheus", include_in_schema=False)
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


@app.get("/metrics", include_in_schema=False)
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



def _get_policy(db: Session, entity_type: str, entity_id) -> "Policy | None":
    return db.query(Policy).filter(
        Policy.entity_type == entity_type,
        Policy.entity_id == entity_id,
    ).first()


def _check_ip(ip: str | None, allowlist: list | None) -> bool:
    """Return True if ip is permitted. None allowlist = unrestricted."""
    if not allowlist or not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in allowlist)
    except ValueError:
        return False


def _check_hours(allowed_from, allowed_to) -> bool:
    """Return True if current UTC time is within the allowed window."""
    if allowed_from is None or allowed_to is None:
        return True
    now_time = datetime.now(timezone.utc).time().replace(tzinfo=None)
    if allowed_from <= allowed_to:
        return allowed_from <= now_time <= allowed_to
    # Overnight window e.g. 22:00-06:00
    return now_time >= allowed_from or now_time <= allowed_to


def _enforce_policies(db: Session, team, registry, source_ip: str | None,
                      x_change_number: str | None, audit_kwargs: dict):
    """
    Evaluate team and registry policies. Raises HTTPException on violation.
    Fires policy.violated webhook on block.
    """
    team_policy = _get_policy(db, "team", team.id)
    reg_policy  = _get_policy(db, "registry", registry.id)

    # --- IP allowlist (team policy first, then registry) ---
    for policy, label in [(team_policy, "team"), (reg_policy, "registry")]:
        if policy and policy.ip_allowlist:
            if not _check_ip(source_ip, policy.ip_allowlist):
                detail = f"Source IP {source_ip} not in {label} allowlist"
                _write_audit(db, "secrets.blocked", "denied", error_detail=detail, **audit_kwargs)
                wh.fire(db, team, "policy.violated",
                        registry={"id": str(registry.id), "name": registry.name},
                        detail=detail)
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    # --- Allowed hours (registry policy) ---
    if reg_policy and (reg_policy.allowed_from or reg_policy.allowed_to):
        if not _check_hours(reg_policy.allowed_from, reg_policy.allowed_to):
            detail = f"Access to registry '{registry.name}' not permitted at this time"
            _write_audit(db, "secrets.blocked", "denied", error_detail=detail, **audit_kwargs)
            wh.fire(db, team, "policy.violated",
                    registry={"id": str(registry.id), "name": registry.name},
                    detail=detail)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    # --- Change number (registry policy overrides global) ---
    if reg_policy and reg_policy.cn_required is not None:
        cn_required = reg_policy.cn_required
    else:
        cn_required = _get_setting_bool(db, "change_number_required", True)
    if cn_required and not x_change_number:
        detail = "X-Change-Number header is required"
        _write_audit(db, "secrets.blocked", "denied", error_detail=detail, **audit_kwargs)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    # --- Rate limit (registry policy overrides global) ---
    if reg_policy and reg_policy.rate_limit_rpm is not None:
        rpm = reg_policy.rate_limit_rpm
    else:
        rpm = _get_setting_int(db, "rate_limit_rpm", 60)
    allowed, _ = rate_limit.check(str(team.id) + ":" + str(registry.id), rpm)
    if not allowed:
        detail = "Rate limit exceeded"
        _write_audit(db, "secrets.blocked", "denied", error_detail=detail, **audit_kwargs)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)

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
        raise HTTPException(status_code=422, detail=f"Invalid time format '{s}', expected HH:MM")


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


@app.get("/admin/api/registries/{reg_id}/policy")
def admin_get_registry_policy(reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    p   = _get_policy(db, "registry", reg.id)
    return _policy_response(p) if p else {}


@app.put("/admin/api/registries/{reg_id}/policy", status_code=200)
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


@app.delete("/admin/api/registries/{reg_id}/policy", status_code=204)
def admin_delete_registry_policy(reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    p   = _get_policy(db, "registry", reg.id)
    if p:
        db.delete(p)
        db.commit()
        _write_change(db, "deleted", "registry", str(reg.id), reg.name,
                      "policy removed", session["username"])


@app.get("/admin/api/teams/{team_id}/policy")
def admin_get_team_policy(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    p    = _get_policy(db, "team", team.id)
    return _policy_response(p) if p else {}


@app.put("/admin/api/teams/{team_id}/policy", status_code=200)
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


@app.delete("/admin/api/teams/{team_id}/policy", status_code=204)
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
    now = datetime.now(timezone.utc)
    for key_row in db.query(TeamRegistryKey).filter(
        TeamRegistryKey.registry_id == registry.id,
        TeamRegistryKey.revoked_at.is_(None),
    ).all():
        key_row.expires_at = key_row.created_at + timedelta(days=max_key_days)
    db.commit()


# ---------------------------------------------------------------------------
# Admin API — webhooks
# ---------------------------------------------------------------------------

class WebhookRequest(BaseModel):
    url:             str
    events:          List[str]
    enabled:         bool = True
    signing_enabled: bool = False


def _webhook_response(w: Webhook) -> dict:
    return {
        "id":              str(w.id),
        "team_id":         str(w.team_id),
        "url":             w.url,
        "events":          w.events,
        "enabled":         w.enabled,
        "signing_enabled": w.signing_enabled,
        "created_at":      w.created_at.isoformat(),
    }


@app.get("/admin/api/teams/{team_id}/webhook")
def admin_get_webhook(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    return _webhook_response(team.webhook) if team.webhook else {}


@app.put("/admin/api/teams/{team_id}/webhook", status_code=200)
def admin_set_webhook(team_id: str, req: WebhookRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team    = _get_team(db, team_id)
    unknown = set(req.events) - wh.ALL_EVENTS
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown event types: {unknown}")

    new_secret = None
    if team.webhook:
        w                 = team.webhook
        w.url             = req.url
        w.events          = req.events
        w.enabled         = req.enabled
        # Enable signing: generate secret if not already set
        if req.signing_enabled and not w.signing_enabled:
            new_secret        = secrets_lib.token_urlsafe(32)
            w.secret          = new_secret
            w.signing_enabled = True
        elif not req.signing_enabled:
            w.signing_enabled = False
            w.secret          = None
    else:
        new_secret = secrets_lib.token_urlsafe(32) if req.signing_enabled else None
        w = Webhook(team_id=team.id, url=req.url, secret=new_secret,
                    signing_enabled=req.signing_enabled,
                    events=req.events, enabled=req.enabled,
                    created_by=session["username"])
        db.add(w)
    db.commit()
    db.refresh(w)
    _write_change(db, "updated", "team", str(team.id), team.name,
                  "webhook configured", session["username"])
    resp = _webhook_response(w)
    if new_secret:
        resp["new_secret"] = new_secret   # returned once when signing first enabled
    return resp


@app.post("/admin/api/teams/{team_id}/webhook/regenerate-secret", status_code=200)
def admin_regenerate_webhook_secret(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    if not team.webhook:
        raise HTTPException(status_code=404, detail="No webhook configured for this team")
    if not team.webhook.signing_enabled:
        raise HTTPException(status_code=400, detail="Signing is not enabled for this webhook")
    new_secret          = secrets_lib.token_urlsafe(32)
    team.webhook.secret = new_secret
    db.commit()
    _write_change(db, "updated", "team", str(team.id), team.name,
                  "webhook secret regenerated", session["username"])
    return {"new_secret": new_secret}


@app.delete("/admin/api/teams/{team_id}/webhook", status_code=204)
def admin_delete_webhook(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    if team.webhook:
        db.delete(team.webhook)
        db.commit()
        _write_change(db, "deleted", "team", str(team.id), team.name,
                      "webhook removed", session["username"])


@app.post("/admin/api/teams/{team_id}/webhook/test", status_code=200)
def admin_test_webhook(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    if not team.webhook:
        raise HTTPException(status_code=404, detail="No webhook configured for this team")
    payload = wh.build_payload(
        "key.expiring_soon",
        team={"id": str(team.id), "name": team.name},
        detail="This is a test delivery from Aegis",
    )
    ok = wh.deliver(db, team.webhook, "key.expiring_soon", payload)
    return {"success": ok}


@app.get("/admin/api/teams/{team_id}/webhook/log")
def admin_webhook_log(team_id: str, page: int = 1, limit: int = 25,
                      session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team  = _get_team(db, team_id)
    limit = min(limit, 100)
    q     = db.query(WebhookLog).filter(WebhookLog.team_id == team.id)\
              .order_by(WebhookLog.fired_at.desc())
    total = q.count()
    rows  = q.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total, "page": page, "limit": limit,
        "rows": [{
            "id":          r.id,
            "event":       r.event,
            "status_code": r.status_code,
            "success":     r.success,
            "attempt":     r.attempt,
            "error":       r.error,
            "fired_at":    r.fired_at.isoformat(),
        } for r in rows],
    }
