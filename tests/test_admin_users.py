"""
Admin user management.

Deleting a user returned 500. The change-log diff read `user.team_id`, a
column User has not had since membership became a many-to-many through
user_teams, so every delete raised AttributeError while building its audit
entry. Nothing covered the endpoint, so nothing noticed.

Requires PostgreSQL (aegis_test).
"""
import uuid

import pytest

from aegis.deps import _hash_pw
from aegis.models import ChangeLog, Team, User, UserTeam
from tests.conftest import ADMIN_CREDS


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def user(db, _schema):
    u = User(username=_unique("member"), password_hash=_hash_pw("correct-horse"),
             role="user", theme="default", created_by="test")
    db.add(u)
    db.commit()
    # Captured before the test runs: after a successful delete, touching the
    # instance would reload a row that is no longer there.
    user_id = u.id
    yield u
    db.expire_all()
    db.query(UserTeam).filter(UserTeam.user_id == user_id).delete()
    db.query(User).filter(User.id == user_id).delete()
    db.commit()


@pytest.fixture
def teams(db, _schema):
    rows = [Team(name=_unique("team"), created_by="test") for _ in range(2)]
    for t in rows:
        db.add(t)
    db.commit()
    yield rows
    for t in rows:
        db.query(UserTeam).filter(UserTeam.team_id == t.id).delete()
        db.delete(t)
    db.commit()


class TestDeleteUser:

    def test_a_user_with_no_memberships_can_be_deleted(self, client, db, user):
        resp = client.delete(f"/admin/api/users/{user.id}", auth=ADMIN_CREDS)
        assert resp.status_code == 204, resp.text
        assert db.query(User).filter(User.id == user.id).first() is None

    def test_a_user_with_memberships_can_be_deleted(self, client, db, user, teams):
        for t in teams:
            db.add(UserTeam(user_id=user.id, team_id=t.id))
        db.commit()

        resp = client.delete(f"/admin/api/users/{user.id}", auth=ADMIN_CREDS)
        assert resp.status_code == 204, resp.text
        assert db.query(User).filter(User.id == user.id).first() is None
        # Memberships go with the account rather than dangling.
        assert db.query(UserTeam).filter(UserTeam.user_id == user.id).count() == 0

    def test_the_audit_entry_records_which_teams_were_reachable(self, client, db, user, teams):
        """
        The diff previously tried to record a single team_id. A user can
        belong to several teams, and what matters afterwards is which ones
        the deleted account could reach.
        """
        for t in teams:
            db.add(UserTeam(user_id=user.id, team_id=t.id))
        db.commit()
        expected = sorted(t.name for t in teams)

        client.delete(f"/admin/api/users/{user.id}", auth=ADMIN_CREDS)

        entry = (db.query(ChangeLog)
                   .filter(ChangeLog.entity_type == "user",
                           ChangeLog.entity_id == str(user.id))
                   .order_by(ChangeLog.id.desc()).first())
        assert entry is not None
        assert entry.action == "deleted"
        assert entry.diff["teams"]["from"] == expected
        assert entry.diff["role"]["from"] == "user"

    def test_the_builtin_admin_cannot_be_deleted(self, client, db):
        admin = db.query(User).filter(User.username == "admin").one()
        resp = client.delete(f"/admin/api/users/{admin.id}", auth=ADMIN_CREDS)
        assert resp.status_code == 400
        assert db.query(User).filter(User.id == admin.id).first() is not None

    def test_an_unknown_user_is_404(self, client):
        assert client.delete(f"/admin/api/users/{uuid.uuid4()}",
                             auth=ADMIN_CREDS).status_code == 404

    def test_a_malformed_id_is_404(self, client):
        assert client.delete("/admin/api/users/not-a-uuid",
                             auth=ADMIN_CREDS).status_code == 404

    def test_deleting_requires_admin(self, client, user):
        assert client.delete(f"/admin/api/users/{user.id}").status_code == 401
