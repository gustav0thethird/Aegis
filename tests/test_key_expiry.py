"""
Integration tests for API key expiry.

Requires PostgreSQL (aegis_test).

max_key_days is documented as enforcing automatic expiry, but nothing checked
expires_at at request time and the rotation scheduler was never started — so a
key with an expiry policy authenticated forever. These tests pin both halves.
"""

from datetime import datetime, timedelta, timezone

import pytest

from aegis import scheduler
from aegis.models import AuditLog, TeamRegistryKey
from tests.test_secrets import _auth_header, _create_scenario


def _key_row(db, plaintext):
    from aegis.keys import hash_key
    return db.query(TeamRegistryKey).filter_by(key_hash=hash_key(plaintext)).one()


def _expire(db, plaintext, when=None):
    row = _key_row(db, plaintext)
    row.expires_at = when or (datetime.now(timezone.utc) - timedelta(days=1))
    db.commit()
    return row


@pytest.fixture(autouse=True)
def enforce_by_default(monkeypatch):
    monkeypatch.delenv("KEY_EXPIRY_MODE", raising=False)


class TestExpiryEnforcement:

    def test_expired_key_is_rejected(self, client, db, monkeypatch):
        """Regression: an expired key used to keep working indefinitely."""
        _obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets", lambda rows, auth: {"x": "v"})
        assert client.get("/secrets", headers=_auth_header(key)).status_code == 200

        _expire(db, key)

        assert client.get("/secrets", headers=_auth_header(key)).status_code == 401

    def test_key_without_an_expiry_still_works(self, client, db, monkeypatch):
        obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})

        assert _key_row(db, key).expires_at is None
        assert client.get("/secrets", headers=_auth_header(key)).status_code == 200
        assert obj.name in client.get("/secrets", headers=_auth_header(key)).json()

    def test_future_expiry_still_works(self, client, db, monkeypatch):
        _obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets", lambda rows, auth: {"x": "v"})

        _expire(db, key, when=datetime.now(timezone.utc) + timedelta(days=5))

        assert client.get("/secrets", headers=_auth_header(key)).status_code == 200

    def test_eso_endpoints_reject_expired_keys_too(self, client, db, monkeypatch):
        """The ESO path shares the auth helper, so it must inherit this."""
        _obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets", lambda rows, auth: {"x": "v"})
        _expire(db, key)

        assert client.get("/eso/v1/secrets", headers=_auth_header(key)).status_code == 401

    def test_rejection_is_audited_with_the_expiry_time(self, client, db):
        _obj, _reg, team, key = _create_scenario(db, client)
        _expire(db, key)

        client.get("/secrets", headers=_auth_header(key))

        entry = db.query(AuditLog).filter(
            AuditLog.team_name == team.name,
            AuditLog.event == "auth.failed",
        ).order_by(AuditLog.timestamp.desc()).first()
        assert entry is not None
        assert "expired" in (entry.error_detail or "").lower()

    def test_warn_mode_allows_but_records(self, client, db, monkeypatch):
        """The migration aid: find out what breaks before it breaks."""
        _obj, _reg, team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets", lambda rows, auth: {"x": "v"})
        _expire(db, key)
        monkeypatch.setenv("KEY_EXPIRY_MODE", "warn")

        assert client.get("/secrets", headers=_auth_header(key)).status_code == 200

        entry = db.query(AuditLog).filter(
            AuditLog.team_name == team.name,
            AuditLog.event == "auth.failed",
        ).order_by(AuditLog.timestamp.desc()).first()
        assert entry.outcome == "warning"


class TestSchedulerLock:
    """Every replica runs a scheduler, so the job must be single-flight."""

    def test_lock_is_acquired_when_free(self):
        with scheduler._job_lock(scheduler._EXPIRY_LOCK_ID) as acquired:
            assert acquired is True

    def test_second_holder_is_refused(self):
        with scheduler._job_lock(scheduler._EXPIRY_LOCK_ID) as first:
            assert first is True
            with scheduler._job_lock(scheduler._EXPIRY_LOCK_ID) as second:
                assert second is False, "two replicas would rotate the same key"

    def test_lock_is_released_on_exit(self):
        with scheduler._job_lock(scheduler._EXPIRY_LOCK_ID):
            pass
        with scheduler._job_lock(scheduler._EXPIRY_LOCK_ID) as acquired:
            assert acquired is True

    def test_lock_is_released_when_the_job_raises(self):
        with pytest.raises(RuntimeError), scheduler._job_lock(scheduler._EXPIRY_LOCK_ID):
            raise RuntimeError("job blew up")
        with scheduler._job_lock(scheduler._EXPIRY_LOCK_ID) as acquired:
            assert acquired is True

    def test_job_skips_while_another_replica_holds_the_lock(self, monkeypatch):
        ran = []
        monkeypatch.setattr(scheduler, "_check_key_expiry_locked", lambda: ran.append(1))

        with scheduler._job_lock(scheduler._EXPIRY_LOCK_ID):
            scheduler.check_key_expiry()

        assert ran == [], "job ran despite the lock being held elsewhere"


class TestScheduledRotation:

    def test_expired_key_is_rotated(self, client, db):
        _obj, reg, team, key = _create_scenario(db, client)
        old_row = _expire(db, key)

        scheduler._check_key_expiry_locked()
        db.expire_all()

        assert db.get(TeamRegistryKey, old_row.id).revoked_at is not None
        replacement = db.query(TeamRegistryKey).filter(
            TeamRegistryKey.team_id == team.id,
            TeamRegistryKey.registry_id == reg.id,
            TeamRegistryKey.revoked_at.is_(None),
        ).one()
        assert replacement.id != old_row.id

    def test_rotated_key_uses_the_shared_format(self, db, client):
        _obj, reg, team, key = _create_scenario(db, client)
        _expire(db, key)

        scheduler._check_key_expiry_locked()
        db.expire_all()

        replacement = db.query(TeamRegistryKey).filter(
            TeamRegistryKey.team_id == team.id,
            TeamRegistryKey.registry_id == reg.id,
            TeamRegistryKey.revoked_at.is_(None),
        ).one()
        assert replacement.key_preview.startswith("sk_")
        assert replacement.key_preview.endswith("...")

    def test_unexpired_keys_are_left_alone(self, client, db):
        _obj, _reg, _team, key = _create_scenario(db, client)
        row = _expire(db, key, when=datetime.now(timezone.utc) + timedelta(days=30))

        scheduler._check_key_expiry_locked()
        db.expire_all()

        assert db.get(TeamRegistryKey, row.id).revoked_at is None
