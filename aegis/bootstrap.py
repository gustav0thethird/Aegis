"""
Admin account bootstrap.

Where the initial admin password comes from, in order of precedence:

  ADMIN_PASSWORD_FILE  Path to a file holding the password. This is how
                       Kubernetes Secret mounts, Docker secrets
                       (/run/secrets/...) and External Secrets Operator
                       deliveries arrive, and it keeps the value out of
                       `docker inspect` and process listings.
  ADMIN_PASSWORD       The password itself. Fine for local development.
  (neither)            A random password is generated on first start and
                       written once to ADMIN_BOOTSTRAP_OUTPUT (default
                       /tmp/aegis-admin.password, mode 0600). It is never
                       logged: audit logs are shipped to SIEMs, and a
                       password in a log line is a password in Splunk.

ADMIN_PASSWORD_SYNC controls what a configured value means after first start:

  bootstrap (default)  First start only. Changing the password in the admin
                       panel sticks; the environment is ignored afterwards.
  always               The configured value is authoritative on every start.
                       Injecting a new value (rotate the Secret, roll the
                       pods) rotates the admin password, and the rotation is
                       recorded in the change log. Use this when the password
                       is owned by a secrets manager rather than a person.
"""
from __future__ import annotations

import logging
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from aegis.models import ChangeLog, User

logger = logging.getLogger("aegis.bootstrap")

# Inside the container /tmp is private to the process user; the chart mounts an
# emptyDir there. Override with ADMIN_BOOTSTRAP_OUTPUT for anything else.
DEFAULT_OUTPUT_PATH = "/tmp/aegis-admin.password"  # nosec B108
GENERATED_BYTES = 24  # token_urlsafe(24) -> 32 characters, ~192 bits


@dataclass(frozen=True)
class AdminPassword:
    value: str
    source: str  # "ADMIN_PASSWORD_FILE", "ADMIN_PASSWORD" or "generated"


def configured_password(env: Optional[dict] = None) -> Optional[AdminPassword]:
    """Return the operator-supplied password, or None if nothing is configured."""
    env = os.environ if env is None else env
    path = (env.get("ADMIN_PASSWORD_FILE") or "").strip()
    if path:
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(f"ADMIN_PASSWORD_FILE={path!r} could not be read: {exc}") from exc
        if not value:
            raise RuntimeError(f"ADMIN_PASSWORD_FILE={path!r} is empty")
        return AdminPassword(value, "ADMIN_PASSWORD_FILE")
    value = env.get("ADMIN_PASSWORD") or ""
    if value:
        return AdminPassword(value, "ADMIN_PASSWORD")
    return None


def generate_password() -> str:
    return secrets.token_urlsafe(GENERATED_BYTES)


def write_generated(password: str, path: str) -> None:
    """
    Write the generated password to `path` readable only by the process user.
    Created with O_EXCL-equivalent semantics via a temp file + replace so a
    pre-existing world-readable file is never reused.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.unlink(missing_ok=True)
    # O_EXCL + O_NOFOLLOW: never write through a file or symlink someone else
    # planted at this path; the mode is applied at creation, not afterwards.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(password + "\n")
    os.replace(tmp, target)


def ensure_admin(db: Session, hash_pw, verify_pw, env: Optional[dict] = None) -> str:
    """
    Make sure an admin account exists and, in `always` mode, that its password
    matches the configured value. Returns a short description of what happened
    (used by tests and the startup log).

    `hash_pw` / `verify_pw` are injected so this module does not import the
    request-layer helpers and so tests can use a cheap hash.
    """
    env = os.environ if env is None else env
    sync = (env.get("ADMIN_PASSWORD_SYNC") or "bootstrap").strip().lower()
    if sync not in ("bootstrap", "always"):
        raise RuntimeError(f"ADMIN_PASSWORD_SYNC must be 'bootstrap' or 'always', got {sync!r}")

    admin = db.query(User).filter(User.username == "admin").first()
    configured = configured_password(env)

    if admin is None:
        if configured is not None:
            pw, source = configured.value, configured.source
        else:
            pw, source = generate_password(), "generated"

        db.add(User(username="admin", password_hash=hash_pw(pw), role="admin",
                    theme="default", created_by="system"))
        db.add(ChangeLog(action="created", entity_type="user", entity_id="admin",
                         entity_name="admin", performed_by="system",
                         detail=f"admin account bootstrapped (password source: {source})"))
        db.commit()

        if source == "generated":
            # Only ever a path. Named without "password" so scanners do not
            # mistake the path for the value.
            out = (env.get("ADMIN_BOOTSTRAP_OUTPUT") or DEFAULT_OUTPUT_PATH).strip()
            try:
                write_generated(pw, out)
            except OSError as exc:
                # Still bootstrapped - API keys and every non-admin path work -
                # but nobody can log in as admin until a password is injected.
                logger.error(
                    "Could not write the generated admin login to %s (%s). Set "
                    "ADMIN_PASSWORD or ADMIN_PASSWORD_FILE and restart with "
                    "ADMIN_PASSWORD_SYNC=always to take control of the account.", out, exc)
                return "seeded-generated-unwritable"
            logger.warning(
                "Wrote a generated admin login to %s (mode 0600) because neither "
                "ADMIN_PASSWORD nor ADMIN_PASSWORD_FILE is set. Read it with "
                "`docker exec <container> cat <that path>` (or kubectl exec), sign in, "
                "and change it in the admin panel. The file is not recreated on later "
                "starts.", out)
            return "seeded-generated"

        logger.info("Seeded admin account from %s", source)
        return f"seeded-{source}"

    # Admin exists.
    if sync == "always" and configured is not None and not verify_pw(configured.value, admin.password_hash):
        admin.password_hash = hash_pw(configured.value)
        db.add(ChangeLog(action="updated", entity_type="user", entity_id=str(admin.id),
                         entity_name="admin", performed_by="system",
                         detail=f"admin password rotated from {configured.source} (ADMIN_PASSWORD_SYNC=always)"))
        db.commit()
        logger.info("Rotated the admin login from %s (ADMIN_PASSWORD_SYNC=always)", configured.source)
        return "rotated"

    return "unchanged"
