"""
Sessions carry identity, not authorisation.

Role and team membership used to be copied into the Redis session at sign-in
and trusted for its whole lifetime, so demoting an administrator or removing
someone from a team did not take effect until the token expired - eight hours
by default. For a product whose job is access control, "revoked, but not for
another eight hours" is not revoked.

The HTTP Basic path already resolved both from the database on every request,
and its comment said so. These tests hold the session path to the same
promise.

Requires PostgreSQL (aegis_test).
"""
import uuid

import pytest

from aegis.deps import _hash_pw
from aegis.models import Team, User, UserTeam


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def account(db, _schema):
    user = User(username=_unique("sess"), password_hash=_hash_pw("correct-horse"),
                role="admin", theme="default", created_by="test")
    db.add(user)
    db.commit()
    yield user
    db.query(UserTeam).filter(UserTeam.user_id == user.id).delete()
    db.delete(user)
    db.commit()


def _login(client, user, password="correct-horse"):
    resp = client.post("/api/login", json={"username": user.username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestRoleChangesApplyImmediately:

    def test_demotion_revokes_admin_on_an_existing_session(self, client, db, account):
        headers = _login(client, account)
        assert client.get("/admin/api/ping", headers=headers).status_code == 200

        account.role = "user"
        db.commit()

        # Same token, no re-login, no waiting for the TTL.
        assert client.get("/admin/api/ping", headers=headers).status_code == 401

    def test_promotion_also_applies_immediately(self, client, db, account):
        account.role = "user"
        db.commit()
        headers = _login(client, account)
        assert client.get("/admin/api/ping", headers=headers).status_code == 401

        account.role = "admin"
        db.commit()
        assert client.get("/admin/api/ping", headers=headers).status_code == 200

    def test_deleted_account_cannot_keep_using_its_session(self, client, db, account):
        headers = _login(client, account)
        assert client.get("/api/me", headers=headers).status_code == 200

        db.query(UserTeam).filter(UserTeam.user_id == account.id).delete()
        db.delete(account)
        db.commit()

        assert client.get("/api/me", headers=headers).status_code == 401


class TestMembershipChangesApplyImmediately:

    def test_membership_is_read_live(self, client, db, account):
        team = Team(name=_unique("team"), created_by="test")
        db.add(team)
        db.commit()
        db.add(UserTeam(user_id=account.id, team_id=team.id))
        db.commit()

        headers = _login(client, account)
        me = client.get("/api/me", headers=headers)
        assert me.status_code == 200
        assert str(team.id) in me.json()["team_ids"]

        # Removing the membership takes effect on the existing session.
        db.query(UserTeam).filter(UserTeam.user_id == account.id,
                                  UserTeam.team_id == team.id).delete()
        db.commit()

        me = client.get("/api/me", headers=headers)
        assert me.status_code == 200
        assert str(team.id) not in me.json()["team_ids"]

        db.delete(team)
        db.commit()


class TestStoredSessionContents:

    def test_the_token_holds_no_authorisation_state(self, client, db, account):
        """
        Nothing may read role or team membership out of the token, so nothing
        is written there for a later change to leave stale.
        """
        import json as _json

        from aegis.deps import _get_redis, _session_key

        resp = client.post("/api/login",
                           json={"username": account.username, "password": "correct-horse"})
        token = resp.json()["token"]
        raw = _get_redis().get(_session_key(token))
        stored = _json.loads(raw)

        assert set(stored) == {"user_id", "issued_at"}
        assert "role" not in stored
        assert "team_ids" not in stored

    def test_changing_the_theme_does_not_reintroduce_authorisation_state(
            self, client, db, account):
        import json as _json

        from aegis.deps import _get_redis, _session_key

        resp = client.post("/api/login",
                           json={"username": account.username, "password": "correct-horse"})
        token = resp.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        assert client.put("/api/me/theme", headers=headers,
                          json={"theme": "midnight"}).status_code == 200

        stored = _json.loads(_get_redis().get(_session_key(token)))
        assert "role" not in stored, "theme update wrote the resolved principal back"
        db.refresh(account)
        assert account.theme == "midnight"
