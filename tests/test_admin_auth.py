"""
Integration tests for admin authentication.

Requires PostgreSQL (aegis_test), same as test_secrets.

The HTTP Basic fallback used to compare the supplied password against
$ADMIN_PASSWORD, which made the bootstrap value a permanent master key that no
change to the users table could revoke. These tests pin the credential to the
database record instead.
"""

import os
import secrets as slib

import bcrypt

from aegis.models import User

PING = "/admin/api/ping"


def _unique(prefix):
    return f"{prefix}_{slib.token_hex(4)}"


def _hash(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _make_user(db, password, role="admin"):
    """Insert a user directly and return (username, user_row)."""
    user = User(
        username=_unique(role),
        password_hash=_hash(password),
        role=role,
        created_by="test",
    )
    db.add(user)
    db.commit()
    return user.username, user


class TestAdminBasicAuth:

    def test_admin_with_correct_password_is_accepted(self, client, db):
        username, _ = _make_user(db, "correct-horse")
        assert client.get(PING, auth=(username, "correct-horse")).status_code == 200

    def test_wrong_password_is_rejected(self, client, db):
        username, _ = _make_user(db, "correct-horse")
        assert client.get(PING, auth=(username, "wrong")).status_code == 401

    def test_env_admin_password_is_not_a_master_key(self, client, db):
        """Regression: $ADMIN_PASSWORD used to authenticate regardless of the DB row."""
        env_password = os.environ["ADMIN_PASSWORD"]
        username, _ = _make_user(db, "something-else")
        assert client.get(PING, auth=(username, env_password)).status_code == 401

    def test_non_admin_user_is_rejected(self, client, db):
        username, _ = _make_user(db, "correct-horse", role="user")
        assert client.get(PING, auth=(username, "correct-horse")).status_code == 401

    def test_password_change_revokes_old_credentials(self, client, db):
        username, user = _make_user(db, "old-password")
        assert client.get(PING, auth=(username, "old-password")).status_code == 200

        user.password_hash = _hash("new-password")
        db.commit()

        assert client.get(PING, auth=(username, "old-password")).status_code == 401
        assert client.get(PING, auth=(username, "new-password")).status_code == 200

    def test_demotion_revokes_admin_access(self, client, db):
        username, user = _make_user(db, "correct-horse")
        assert client.get(PING, auth=(username, "correct-horse")).status_code == 200

        user.role = "user"
        db.commit()

        assert client.get(PING, auth=(username, "correct-horse")).status_code == 401

    def test_deleted_user_loses_access(self, client, db):
        username, user = _make_user(db, "correct-horse")
        assert client.get(PING, auth=(username, "correct-horse")).status_code == 200

        db.delete(user)
        db.commit()

        assert client.get(PING, auth=(username, "correct-horse")).status_code == 401

    def test_unknown_user_is_rejected(self, client):
        assert client.get(PING, auth=("nobody", "whatever")).status_code == 401

    def test_missing_credentials_are_rejected(self, client):
        assert client.get(PING).status_code == 401

    def test_malformed_basic_header_is_rejected(self, client):
        resp = client.get(PING, headers={"Authorization": "Basic not-base64!!"})
        assert resp.status_code == 401

    def test_seeded_admin_still_works(self, client):
        """The documented bootstrap flow must keep working for the seeded account."""
        from tests.conftest import ADMIN_CREDS

        assert client.get(PING, auth=ADMIN_CREDS).status_code == 200
