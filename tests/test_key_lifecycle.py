"""
Every path that issues a key behaves the same way.

Four of them mint keys - registry assignment, admin rotation, the CI/CD
inbound webhook and the expiry scheduler - and they had drifted:

                        expiry          revokes old   change log   webhook
  assignment            registry only   n/a           yes          no
  admin rotation        none            yes           yes          yes
  inbound rotation      none            yes           no           no
  scheduler             effective       yes           no           yes

Two of those were security bugs. A key with no expires_at is invisible to the
expiry scheduler, which selects on `expires_at IS NOT NULL`, so a policy
demanding 24-hour keys quietly produced permanent ones. And the assignment
path read max_key_days from the registry policy alone, ignoring a team policy.

These tests are written as a matrix on purpose: the point is not that each
path works, it is that they agree.

Requires PostgreSQL (aegis_test).
"""
import uuid
from datetime import datetime, timezone

import pytest

from aegis import keylifecycle
from aegis.models import (
    Policy,
    Registry,
    Team,
    TeamRegistry,
    TeamRegistryKey,
)
from tests.conftest import ADMIN_CREDS


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def pair(db, _schema):
    team = Team(name=_unique("team"), created_by="test")
    reg = Registry(name=_unique("reg"), created_by="test")
    db.add(team)
    db.add(reg)
    db.commit()
    yield team, reg
    db.query(TeamRegistryKey).filter(TeamRegistryKey.team_id == team.id).delete()
    db.query(TeamRegistry).filter(TeamRegistry.team_id == team.id).delete()
    db.query(Policy).filter(Policy.entity_id.in_([team.id, reg.id])).delete(synchronize_session=False)
    db.delete(team)
    db.delete(reg)
    db.commit()


def _policy(db, entity_type, entity_id, **fields):
    db.add(Policy(entity_type=entity_type, entity_id=entity_id, created_by="test", **fields))
    db.commit()


def _active_key(db, team, reg):
    return (db.query(TeamRegistryKey)
              .filter(TeamRegistryKey.team_id == team.id,
                      TeamRegistryKey.registry_id == reg.id,
                      TeamRegistryKey.revoked_at.is_(None))
              .one())


# --------------------------------------------------------------------------
# The four issuance paths, each reduced to "make a key for this pair"
# --------------------------------------------------------------------------

def _via_assignment(client, db, team, reg):
    resp = client.post(f"/admin/api/teams/{team.id}/registries/{reg.id}", auth=ADMIN_CREDS)
    assert resp.status_code == 201, resp.text


def _via_admin_rotation(client, db, team, reg):
    _via_assignment(client, db, team, reg)
    resp = client.post(f"/admin/api/teams/{team.id}/registries/{reg.id}/rotate-key",
                       auth=ADMIN_CREDS)
    assert resp.status_code == 200, resp.text


def _via_scheduler(client, db, team, reg):
    from aegis import scheduler
    _via_assignment(client, db, team, reg)
    db.expire_all()
    scheduler._rotate_key(db, _active_key(db, team, reg), reason="scheduled_expiry")


def _via_service(client, db, team, reg):
    """
    The inbound webhook path, minus its authentication wrapper.

    Assigns first, because CI rotates a key the team already has; rotating
    nothing would not exercise revocation.
    """
    _via_assignment(client, db, team, reg)
    db.expire_all()
    keylifecycle.issue(db, team, reg, actor="inbound:test", reason="inbound_rotation")


ALL_PATHS = [
    pytest.param(_via_assignment, id="assignment"),
    pytest.param(_via_admin_rotation, id="admin-rotation"),
    pytest.param(_via_scheduler, id="scheduler"),
    pytest.param(_via_service, id="inbound-rotation"),
]


class TestExpiryIsAppliedEverywhere:

    @pytest.mark.parametrize("path", ALL_PATHS)
    def test_registry_policy_sets_expiry(self, client, db, pair, path):
        team, reg = pair
        _policy(db, "registry", reg.id, max_key_days=30)
        path(client, db, team, reg)
        db.expire_all()
        key = _active_key(db, team, reg)
        assert key.expires_at is not None, "key would never be seen by the expiry scheduler"
        days = (key.expires_at - datetime.now(timezone.utc)).days
        assert 28 <= days <= 30

    @pytest.mark.parametrize("path", ALL_PATHS)
    def test_team_policy_alone_sets_expiry(self, client, db, pair, path):
        """The assignment path read the registry policy only, so this was null."""
        team, reg = pair
        _policy(db, "team", team.id, max_key_days=1)
        path(client, db, team, reg)
        db.expire_all()
        key = _active_key(db, team, reg)
        assert key.expires_at is not None
        assert (key.expires_at - datetime.now(timezone.utc)).total_seconds() < 60 * 60 * 25

    @pytest.mark.parametrize("path", ALL_PATHS)
    def test_shortest_policy_wins(self, client, db, pair, path):
        team, reg = pair
        _policy(db, "team", team.id, max_key_days=90)
        _policy(db, "registry", reg.id, max_key_days=7)
        path(client, db, team, reg)
        db.expire_all()
        key = _active_key(db, team, reg)
        assert (key.expires_at - datetime.now(timezone.utc)).days <= 7

    @pytest.mark.parametrize("path", ALL_PATHS)
    def test_no_policy_means_no_expiry(self, client, db, pair, path):
        team, reg = pair
        path(client, db, team, reg)
        db.expire_all()
        assert _active_key(db, team, reg).expires_at is None


class TestRotationInvariants:

    @pytest.mark.parametrize("path", [p for p in ALL_PATHS if p.id != "assignment"])
    def test_exactly_one_key_stays_active(self, client, db, pair, path):
        team, reg = pair
        path(client, db, team, reg)
        db.expire_all()
        active = (db.query(TeamRegistryKey)
                    .filter(TeamRegistryKey.team_id == team.id,
                            TeamRegistryKey.registry_id == reg.id,
                            TeamRegistryKey.revoked_at.is_(None)).all())
        assert len(active) == 1, "a rotation must leave no overlap"

    @pytest.mark.parametrize("path", [p for p in ALL_PATHS if p.id != "assignment"])
    def test_the_replaced_key_is_revoked(self, client, db, pair, path):
        team, reg = pair
        path(client, db, team, reg)
        db.expire_all()
        revoked = (db.query(TeamRegistryKey)
                     .filter(TeamRegistryKey.team_id == team.id,
                             TeamRegistryKey.revoked_at.isnot(None)).all())
        assert revoked, "the key that was replaced is still usable"

    @pytest.mark.parametrize("path", ALL_PATHS)
    def test_preview_format_is_identical(self, client, db, pair, path):
        team, reg = pair
        path(client, db, team, reg)
        db.expire_all()
        preview = _active_key(db, team, reg).key_preview
        assert preview.startswith("sk_") and preview.endswith("...")
        assert len(preview) == 13

    @pytest.mark.parametrize("path", ALL_PATHS)
    def test_plaintext_is_never_stored(self, client, db, pair, path):
        team, reg = pair
        path(client, db, team, reg)
        db.expire_all()
        key = _active_key(db, team, reg)
        assert len(key.key_hash) == 64                    # sha256 hex
        assert not key.key_hash.startswith("sk_")


class TestAuditTrail:

    @pytest.mark.parametrize("path", ALL_PATHS)
    def test_every_issuance_is_change_logged(self, client, db, pair, path):
        """The inbound path used to leave no trail at all."""
        from aegis.models import ChangeLog
        team, reg = pair
        path(client, db, team, reg)
        entries = (db.query(ChangeLog)
                     .filter(ChangeLog.entity_type == "team",
                             ChangeLog.entity_id == str(team.id)).all())
        assert entries, "issuing a credential left no change-log entry"
        assert any("key_preview" in (e.diff or {}) for e in entries)

    def test_the_recorded_expiry_matches_the_key(self, client, db, pair):
        team, reg = pair
        from aegis.models import ChangeLog
        _policy(db, "registry", reg.id, max_key_days=14)
        _via_assignment(client, db, team, reg)
        db.expire_all()
        key = _active_key(db, team, reg)
        entry = (db.query(ChangeLog)
                   .filter(ChangeLog.entity_id == str(team.id))
                   .order_by(ChangeLog.id.desc()).first())
        assert entry.diff["expires_at"]["to"] == key.expires_at.isoformat()


class TestServiceUnits:

    def test_effective_expiry_is_none_without_policy(self, db, pair):
        team, reg = pair
        assert keylifecycle.effective_expiry(db, team, reg) is None

    def test_revoking_returns_the_previous_preview(self, db, pair):
        team, reg = pair
        row, _ = keylifecycle.issue(db, team, reg, actor="test", reason="assignment",
                                    revoke_existing=False, notify=False)
        previous = keylifecycle.revoke_active_keys(db, team, reg)
        assert previous == row.key_preview
