"""
Tests for the admin account bootstrap (aegis/bootstrap.py).

Requires PostgreSQL (aegis_test) for the User/ChangeLog rows; password hashing
is swapped for a cheap reversible stand-in so the suite stays fast.

The behaviours worth protecting:
  - no configured password never means "changeme": a random one is generated,
    written to a 0600 file and NOT logged
  - ADMIN_PASSWORD_FILE beats ADMIN_PASSWORD (that is how Secrets arrive)
  - in the default mode a later environment change does not touch an
    existing account; in `always` mode it rotates it and leaves an audit row
"""
import logging
import os
import stat

import pytest

from aegis import bootstrap
from aegis.models import ChangeLog, User


def _hash(pw: str) -> str:
    return "h:" + pw


def _verify(pw: str, hashed: str) -> bool:
    return hashed == "h:" + pw


@pytest.fixture
def clean_admin(db, _schema):
    """
    Remove the admin account (and its system change-log rows) for the test,
    then put it back exactly as app startup would have, because the other
    integration suites sign in with conftest.ADMIN_CREDS.
    """
    from aegis.deps import _hash_pw, _verify_pw
    from tests.conftest import ADMIN_CREDS

    def _wipe():
        (db.query(ChangeLog)
           .filter(ChangeLog.entity_name == "admin", ChangeLog.performed_by == "system")
           .delete())
        db.query(User).filter(User.username == "admin").delete()
        db.commit()
    _wipe()
    yield db
    _wipe()
    bootstrap.ensure_admin(db, _hash_pw, _verify_pw, env={"ADMIN_PASSWORD": ADMIN_CREDS[1]})


def _admin(db):
    return db.query(User).filter(User.username == "admin").one()


def test_generates_random_password_when_nothing_configured(clean_admin, tmp_path, caplog):
    out = tmp_path / "admin.password"
    env = {"ADMIN_PASSWORD_OUTPUT": str(out)}

    with caplog.at_level(logging.WARNING, logger="aegis.bootstrap"):
        result = bootstrap.ensure_admin(clean_admin, _hash, _verify, env=env)

    assert result == "seeded-generated"
    pw = out.read_text().strip()
    assert len(pw) >= 32
    assert _verify(pw, _admin(clean_admin).password_hash)
    # Readable by owner only.
    if os.name != "nt":
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    # The password itself never reaches the log; the path does.
    assert pw not in caplog.text
    assert str(out) in caplog.text
    row = clean_admin.query(ChangeLog).filter(ChangeLog.entity_name == "admin").one()
    assert "generated" in row.detail and row.performed_by == "system"


def test_generated_password_is_not_changeme(clean_admin, tmp_path):
    env = {"ADMIN_PASSWORD_OUTPUT": str(tmp_path / "p")}
    bootstrap.ensure_admin(clean_admin, _hash, _verify, env=env)
    assert not _verify("changeme", _admin(clean_admin).password_hash)


def test_env_password_is_used(clean_admin):
    result = bootstrap.ensure_admin(clean_admin, _hash, _verify, env={"ADMIN_PASSWORD": "from-env"})
    assert result == "seeded-ADMIN_PASSWORD"
    assert _verify("from-env", _admin(clean_admin).password_hash)


def test_file_takes_precedence_over_env(clean_admin, tmp_path):
    f = tmp_path / "admin-password"
    f.write_text("from-file\n")
    env = {"ADMIN_PASSWORD": "from-env", "ADMIN_PASSWORD_FILE": str(f)}
    result = bootstrap.ensure_admin(clean_admin, _hash, _verify, env=env)
    assert result == "seeded-ADMIN_PASSWORD_FILE"
    assert _verify("from-file", _admin(clean_admin).password_hash)


def test_unreadable_or_empty_file_is_an_error(clean_admin, tmp_path):
    with pytest.raises(RuntimeError, match="could not be read"):
        bootstrap.ensure_admin(clean_admin, _hash, _verify,
                               env={"ADMIN_PASSWORD_FILE": str(tmp_path / "missing")})
    empty = tmp_path / "empty"
    empty.write_text("\n")
    with pytest.raises(RuntimeError, match="is empty"):
        bootstrap.ensure_admin(clean_admin, _hash, _verify, env={"ADMIN_PASSWORD_FILE": str(empty)})


def test_bootstrap_mode_ignores_later_changes(clean_admin):
    bootstrap.ensure_admin(clean_admin, _hash, _verify, env={"ADMIN_PASSWORD": "first"})
    result = bootstrap.ensure_admin(clean_admin, _hash, _verify, env={"ADMIN_PASSWORD": "second"})
    assert result == "unchanged"
    assert _verify("first", _admin(clean_admin).password_hash)


def test_always_mode_rotates_and_audits(clean_admin):
    bootstrap.ensure_admin(clean_admin, _hash, _verify, env={"ADMIN_PASSWORD": "first"})
    env = {"ADMIN_PASSWORD": "second", "ADMIN_PASSWORD_SYNC": "always"}
    assert bootstrap.ensure_admin(clean_admin, _hash, _verify, env=env) == "rotated"
    assert _verify("second", _admin(clean_admin).password_hash)
    rows = clean_admin.query(ChangeLog).filter(ChangeLog.entity_name == "admin").all()
    assert any("rotated" in r.detail and r.action == "updated" for r in rows)
    # Same value again is a no-op, not another audit row.
    assert bootstrap.ensure_admin(clean_admin, _hash, _verify, env=env) == "unchanged"
    assert len(clean_admin.query(ChangeLog).filter(ChangeLog.entity_name == "admin").all()) == len(rows)


def test_always_mode_without_a_configured_value_is_a_noop(clean_admin):
    bootstrap.ensure_admin(clean_admin, _hash, _verify, env={"ADMIN_PASSWORD": "first"})
    assert bootstrap.ensure_admin(clean_admin, _hash, _verify, env={"ADMIN_PASSWORD_SYNC": "always"}) == "unchanged"
    assert _verify("first", _admin(clean_admin).password_hash)


def test_invalid_sync_mode_is_rejected(clean_admin):
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD_SYNC"):
        bootstrap.ensure_admin(clean_admin, _hash, _verify, env={"ADMIN_PASSWORD_SYNC": "sometimes"})
