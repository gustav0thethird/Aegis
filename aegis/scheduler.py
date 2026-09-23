"""
scheduler.py — Background jobs for Aegis.

Jobs:
  check_key_expiry  — runs daily; warns on keys expiring soon, auto-rotates expired keys.

Uses APScheduler (in-process). Scheduler state is not persisted — on restart it will
re-check immediately, which is safe (idempotent).

Every replica runs a scheduler, so each job takes a Postgres advisory lock and
skips if another replica already holds it. Without that, two replicas rotate the
same key at the same moment and each fires a key.rotated webhook carrying a
different plaintext — the team ends up with two "new" keys, only one of which
survives.
"""

import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import text as sa_text

from aegis import keylifecycle
from aegis import webhook as wh
from aegis.database import SessionLocal, engine
from aegis.models import Setting, TeamRegistryKey, WebhookLog

logger = logging.getLogger("aegis.scheduler")

_scheduler: BackgroundScheduler | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_setting(db, key: str, default: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row and row.value is not None else default


# One stable 64-bit id per job. Postgres releases advisory locks automatically
# when the holding session ends, so a crashed replica does not wedge the job.
_EXPIRY_LOCK_ID = 0x41656769735F4B45   # "Aegis_KE"


@contextmanager
def _job_lock(lock_id: int):
    """
    Yield True if this process acquired the job lock, False if another holds it.

    Takes its own connection rather than borrowing the job's Session: a Session
    hands its connection back to the pool on commit, and a session-scoped
    advisory lock goes with it — the lock would be dropped halfway through the
    very work it is protecting.
    """
    conn = engine.connect()
    try:
        acquired = bool(
            conn.execute(sa_text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}).scalar()
        )
        try:
            yield acquired
        finally:
            if acquired:
                conn.execute(sa_text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id})
    finally:
        conn.close()


def _rotate_key(db, key_row: TeamRegistryKey, reason: str) -> str:
    """
    Rotate the key behind key_row. Returns the plaintext.

    The scheduler has no caller to hand the new key to, so the webhook is how
    the team learns to collect it. Issuance itself is shared with every other
    rotation path.
    """
    team     = key_row.team
    registry = key_row.registry
    _row, plaintext = keylifecycle.issue(
        db, team, registry, actor="system", reason=reason, notify=False)
    logger.info("Auto-rotated key team=%s registry=%s reason=%s", team.name, registry.name, reason)
    return plaintext


# ---------------------------------------------------------------------------
# Job: key expiry check
# ---------------------------------------------------------------------------

def check_key_expiry() -> None:
    """
    Runs daily. For each active key with expires_at set:
      - If within warning_days: fire key.expiring_soon webhook (once per day at most — checked via webhook_log)
      - If past expires_at: auto-rotate, fire key.rotated webhook with new key
    """
    with _job_lock(_EXPIRY_LOCK_ID) as acquired:
        if not acquired:
            logger.debug("check_key_expiry skipped — another replica holds the lock")
            return
        _check_key_expiry_locked()


def _check_key_expiry_locked() -> None:
    db = SessionLocal()
    try:
        now          = datetime.now(timezone.utc)
        warning_days = int(_get_setting(db, "key_warning_days", "7"))
        warn_cutoff  = now + timedelta(days=warning_days)

        active_keys = db.query(TeamRegistryKey).filter(
            TeamRegistryKey.revoked_at.is_(None),
            TeamRegistryKey.expires_at.isnot(None),
        ).all()

        for key_row in active_keys:
            team     = key_row.team
            registry = key_row.registry

            if key_row.expires_at <= now:
                # Expired — auto-rotate
                plaintext = _rotate_key(db, key_row, reason="scheduled_expiry")
                new_key_row = db.query(TeamRegistryKey).filter(
                    TeamRegistryKey.team_id == team.id,
                    TeamRegistryKey.registry_id == registry.id,
                    TeamRegistryKey.revoked_at.is_(None),
                ).first()
                wh.fire(db, team, "key.rotated",
                        registry={"id": str(registry.id), "name": registry.name},
                        new_key=plaintext,
                        key_preview=new_key_row.key_preview if new_key_row else None,
                        reason="scheduled_expiry")

            elif key_row.expires_at <= warn_cutoff:
                # Expiring soon — warn (but only if we haven't warned in the last 23h)
                webhook = team.webhook
                if not webhook or not webhook.enabled:
                    continue
                already_warned = db.query(WebhookLog).filter(
                    WebhookLog.webhook_id == webhook.id,
                    WebhookLog.event == "key.expiring_soon",
                    WebhookLog.success.is_(True),
                    WebhookLog.fired_at >= now - timedelta(hours=23),
                ).first()
                if not already_warned:
                    wh.fire(db, team, "key.expiring_soon",
                            registry={"id": str(registry.id), "name": registry.name},
                            key_preview=key_row.key_preview,
                            reason="scheduled_warning",
                            detail=f"Key expires at {key_row.expires_at.isoformat()}")

    except Exception as exc:
        logger.error("check_key_expiry failed: %s", exc)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start() -> None:
    """Start the background scheduler. Call once at application startup."""
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(check_key_expiry, trigger="interval", hours=24,
                       id="check_key_expiry", replace_existing=True,
                       next_run_time=datetime.now(timezone.utc))  # run immediately on startup too
    _scheduler.start()
    logger.info("Scheduler started")


def stop() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
