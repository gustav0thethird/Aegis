"""
deps.py — shared dependencies and helpers for the API routers.

These were previously inline in api.py, where a helper could be defined a
thousand lines after its first use and only resolved because Python looks names
up at call time. Collecting them here makes the dependency direction explicit:
routers import from deps, never the reverse.
"""


import contextlib
import ipaddress
import json
import logging
import os
import secrets as secrets_lib
import uuid
from datetime import datetime, timezone
from typing import Optional

import bcrypt as _bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBearer
from sqlalchemy.orm import Session

from aegis import keys, rate_limit, secret_cache, url_guard
from aegis import webhook as wh
from aegis.broker import fetch_secrets, load_auth
from aegis.database import get_db
from aegis.models import (
    AuditLog,
    ChangeLog,
    Object,
    Policy,
    Registry,
    Setting,
    Team,
    TeamRegistryKey,
    User,
)
from aegis.siem import build_event, emit

logger = logging.getLogger("aegis")

bearer     = HTTPBearer(auto_error=False)
admin_auth = HTTPBasic(auto_error=False)


def _hash_pw(pw: str) -> str:
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()


def _verify_pw(pw: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _hash_key(key: str) -> str:
    return keys.hash_key(key)


def _validated_url(value: Optional[str], field: str) -> Optional[str]:
    """Reject SSRF-unsafe outbound URLs before they are persisted."""
    if not value:
        return value
    try:
        return url_guard.validate_url(value, field)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _generate_key() -> str:
    return keys.generate_key()


def _eso_registry_extract_allowed() -> bool:
    """
    Whether /eso/v1/secrets may hand a workload an entire registry.

    Convenient, but it grants everything in the registry to any workload holding
    the key. Deployments that want per-object grants turn it off.
    """
    return os.environ.get("ESO_ALLOW_REGISTRY_EXTRACT", "true").strip().lower() != "false"


def _key_expiry_enforced() -> bool:
    """
    Whether an expired key is rejected (default) or merely recorded.

    "warn" exists so an operator turning this on for the first time can find
    out which integrations are running on expired keys before those
    integrations break. It is a migration aid, not a setting to leave on.
    """
    return os.environ.get("KEY_EXPIRY_MODE", "enforce").strip().lower() != "warn"


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
    with contextlib.suppress(Exception):
        _get_redis().delete(_session_key(token))


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

    # Fall back to HTTP Basic (for curl / API access). Credentials are verified
    # against the users table — never against ADMIN_PASSWORD, which is a
    # bootstrap-only value — so password changes, role changes and account
    # deletion all take effect immediately.
    from fastapi.security.utils import get_authorization_scheme_param
    auth_header = request.headers.get("Authorization", "")
    scheme, credentials = get_authorization_scheme_param(auth_header)
    if scheme.lower() == "basic":
        import base64
        try:
            decoded = base64.b64decode(credentials).decode("utf-8")
            username, sep, password = decoded.partition(":")
        except Exception:
            username = sep = password = ""
        if sep and username:
            user = db.query(User).filter(User.username == username).first()
            if user and user.role == "admin" and _verify_pw(password, user.password_hash):
                return {
                    "user_id":  str(user.id),
                    "username": user.username,
                    "role":     user.role,
                    "team_id":  None,
                    "team_ids": [str(m.team_id) for m in (user.team_memberships or [])],
                    "theme":    user.theme,
                }

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


def _authenticate_registry_key(db: Session, api_key: str, source_ip, user_agent):
    """
    Resolve an API key to its team_registry_keys row, or raise 401.

    Shared by /secrets and the External Secrets Operator endpoints so both are
    authenticated, audited and revoked identically.
    """
    key_hash = _hash_key(api_key)

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

    # An expired key must stop working. max_key_days is documented as enforcing
    # expiry, but nothing checked expires_at at request time, so keys with an
    # expiry policy kept authenticating indefinitely.
    if key_row.expires_at and key_row.expires_at <= datetime.now(timezone.utc):
        enforced = _key_expiry_enforced()
        logger.warning("Expired key (hash prefix: %s...) expired_at=%s enforced=%s",
                       key_hash[:8], key_row.expires_at.isoformat(), enforced)
        _write_audit(db, "auth.failed", "denied" if enforced else "warning",
                     registry_id=str(key_row.registry_id), registry_name=key_row.registry.name,
                     team_id=str(key_row.team_id), team_name=key_row.team.name,
                     key_preview=key_row.key_preview, source_ip=source_ip, user_agent=user_agent,
                     error_detail=f"Key expired at {key_row.expires_at.isoformat()}")
        if enforced:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    return key_row


def _fetch_for_key(db: Session, key_row, x_change_number, source_ip, user_agent,
                   only: Optional[str] = None, use_cache: bool = False) -> dict:
    """
    Enforce policy for the key's team/registry and fetch its objects.

    only — restrict the fetch to a single object name. Policy is still evaluated
    against the whole registry, because the registry is the unit of
    authorisation; only the vault round-trip is narrowed.

    use_cache — serve a recent identical fetch from the in-process cache instead
    of calling the vault again. Only the vault round trip is skipped: policy is
    still enforced and the request is still audited, so a cache hit is
    indistinguishable in the audit log from a miss.

    Returns {object_name: plaintext}. Raises the same HTTP errors /secrets has
    always raised, and writes the same audit records.
    """
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
    if only is not None:
        object_rows = [o for o in object_rows if o["name"] == only]
        if not object_rows:
            _write_audit(db, "secrets.fetched", "denied",
                         change_number=x_change_number,
                         registry_id=str(registry.id), registry_name=registry.name,
                         team_id=str(team.id), team_name=team.name,
                         objects=[only], key_preview=key_preview,
                         source_ip=source_ip, user_agent=user_agent,
                         error_detail=f"Object '{only}' is not in registry '{registry.name}'")
            raise HTTPException(status_code=404, detail="Secret not found")

    object_names = [o["name"] for o in object_rows]
    logger.info("Request team=%s registry=%s change=%s objects=%s",
                team.name, registry.name, x_change_number, object_names)

    cache_key = secret_cache.make_key(key_row.key_hash, only or "*")
    cached = secret_cache.get(cache_key) if use_cache else None
    if cached is not None:
        _write_audit(db, "secrets.fetched", "success",
                     change_number=x_change_number,
                     registry_id=str(registry.id), registry_name=registry.name,
                     team_id=str(team.id), team_name=team.name,
                     objects=object_names, key_preview=key_preview,
                     source_ip=source_ip, user_agent=user_agent)
        return cached

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
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    if use_cache:
        secret_cache.put(cache_key, fetched)

    _write_audit(db, "secrets.fetched", "success",
                 change_number=x_change_number,
                 registry_id=str(registry.id), registry_name=registry.name,
                 team_id=str(team.id), team_name=team.name,
                 objects=object_names, key_preview=key_preview,
                 source_ip=source_ip, user_agent=user_agent)
    return fetched

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _write_change(db: Session, action: str, entity_type: str, entity_id: str,
                  entity_name: str, detail: Optional[str] = None,
                  performed_by: str = "admin", diff: Optional[dict] = None):
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
        if policy and policy.ip_allowlist and not _check_ip(source_ip, policy.ip_allowlist):
                detail = f"Source IP {source_ip} not in {label} allowlist"
                _write_audit(db, "secrets.blocked", "denied", error_detail=detail, **audit_kwargs)
                wh.fire(db, team, "policy.violated",
                        registry={"id": str(registry.id), "name": registry.name},
                        detail=detail)
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    # --- Allowed hours (registry policy) ---
    if (reg_policy and (reg_policy.allowed_from or reg_policy.allowed_to)
            and not _check_hours(reg_policy.allowed_from, reg_policy.allowed_to)):
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
        raise HTTPException(status_code=404, detail="Registry not found") from None
    reg = db.query(Registry).filter(Registry.id == uid).first()
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    return reg


def _get_team(db: Session, team_id: str) -> Team:
    try:
        uid = uuid.UUID(team_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Team not found") from None
    team = db.query(Team).filter(Team.id == uid).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    return team


def _authenticate_team_webhook(db: Session, team_id_str: str, request: Request) -> Team:
    """
    Resolve a team from its id and verify the caller holds its inbound webhook
    secret. Shared by the inbound action endpoint and scan ingest.
    """
    try:
        tid = uuid.UUID(team_id_str)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found") from None

    team = db.get(Team, tid)
    if not team:
        raise HTTPException(status_code=404, detail="Not found")

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = auth_header[7:]

    hook = team.webhook
    if not hook or not hook.secret or not hook.signing_enabled:
        raise HTTPException(
            status_code=403,
            detail="Inbound webhook not configured (enable signing and set secret)")

    import hmac as _hmac2
    if not _hmac2.compare_digest(token, hook.secret):
        raise HTTPException(status_code=403, detail="Invalid token")

    return team


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
