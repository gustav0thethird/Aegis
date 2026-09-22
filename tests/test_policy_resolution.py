"""
Effective policy resolution.

The documented model was "registry overrides team overrides global", but each
field behaved differently: the IP allowlist required both levels to pass,
allowed hours consulted only the registry, change number and rate limit took
the registry or fell back to global with the team ignored entirely, and the
expiry scheduler read the registry alone. Operators configure from the
documentation, so this is tested as a matrix rather than field by field.

The implemented rule is most-restrictive-wins, not override - see
aegis/policy.py. These tests pin that down, including the cases where it
differs from an override model.

Requires PostgreSQL (aegis_test).
"""
import uuid
from datetime import time

import pytest

from aegis import policy as policy_mod
from aegis.models import Policy, Registry, Team


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
    db.query(Policy).filter(Policy.entity_id.in_([team.id, reg.id])).delete(synchronize_session=False)
    db.delete(team)
    db.delete(reg)
    db.commit()


def _policy(db, entity_type, entity_id, **fields):
    db.add(Policy(entity_type=entity_type, entity_id=entity_id, created_by="test", **fields))
    db.commit()


class TestRateLimit:
    """Numeric limits: the lowest applicable value wins."""

    def test_global_only(self, db, pair):
        team, reg = pair
        assert policy_mod.resolve(db, team, reg, global_rate_limit_rpm=60).rate_limit_rpm == 60

    def test_team_narrows_global(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, rate_limit_rpm=30)
        assert policy_mod.resolve(db, team, reg, global_rate_limit_rpm=60).rate_limit_rpm == 30

    def test_team_alone_was_previously_ignored(self, db, pair):
        """The old code read the registry or global; a team limit did nothing."""
        team, reg = pair
        _policy(db, "team", team.id, rate_limit_rpm=10)
        assert policy_mod.resolve(db, team, reg, global_rate_limit_rpm=60).rate_limit_rpm == 10

    def test_registry_cannot_raise_a_team_limit(self, db, pair):
        """Under an override model this would be 600. Adding a policy must not widen access."""
        team, reg = pair
        _policy(db, "team", team.id, rate_limit_rpm=30)
        _policy(db, "registry", reg.id, rate_limit_rpm=600)
        assert policy_mod.resolve(db, team, reg, global_rate_limit_rpm=60).rate_limit_rpm == 30

    def test_registry_narrows_further(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, rate_limit_rpm=30)
        _policy(db, "registry", reg.id, rate_limit_rpm=5)
        assert policy_mod.resolve(db, team, reg, global_rate_limit_rpm=60).rate_limit_rpm == 5


class TestChangeNumber:

    def test_global_default_applies(self, db, pair):
        team, reg = pair
        assert policy_mod.resolve(db, team, reg, global_cn_required=True).cn_required is True
        assert policy_mod.resolve(db, team, reg, global_cn_required=False).cn_required is False

    def test_either_level_can_require_it(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, cn_required=True)
        assert policy_mod.resolve(db, team, reg, global_cn_required=False).cn_required is True

    def test_registry_cannot_switch_off_a_team_requirement(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, cn_required=True)
        _policy(db, "registry", reg.id, cn_required=False)
        assert policy_mod.resolve(db, team, reg, global_cn_required=False).cn_required is True


class TestIPAllowlist:
    """Restrictions accumulate: the caller must satisfy every list that is set."""

    def test_no_policy_means_no_restriction(self, db, pair):
        team, reg = pair
        assert policy_mod.resolve(db, team, reg).ip_allowlists == []

    def test_both_levels_are_collected(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, ip_allowlist=["10.0.0.0/8"])
        _policy(db, "registry", reg.id, ip_allowlist=["10.1.0.0/16"])
        eff = policy_mod.resolve(db, team, reg)
        assert sorted(eff.sources()) == ["registry", "team"]
        assert len(eff.ip_allowlists) == 2

    def test_a_registry_list_does_not_replace_the_team_list(self, db, pair):
        """Override semantics would drop the team allowlist and widen access."""
        team, reg = pair
        _policy(db, "team", team.id, ip_allowlist=["10.0.0.0/8"])
        _policy(db, "registry", reg.id, ip_allowlist=["0.0.0.0/0"])
        labels = [label for label, _ in policy_mod.resolve(db, team, reg).ip_allowlists]
        assert "team" in labels


class TestAllowedHours:

    def test_team_window_is_no_longer_ignored(self, db, pair):
        """Previously only the registry window was evaluated."""
        team, reg = pair
        _policy(db, "team", team.id, allowed_from=time(9, 0), allowed_to=time(17, 0))
        eff = policy_mod.resolve(db, team, reg)
        assert [label for label, _, _ in eff.hour_windows] == ["team"]

    def test_both_windows_apply(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, allowed_from=time(9, 0), allowed_to=time(17, 0))
        _policy(db, "registry", reg.id, allowed_from=time(12, 0), allowed_to=time(13, 0))
        assert len(policy_mod.resolve(db, team, reg).hour_windows) == 2


class TestKeyExpiry:
    """Issuance, rotation and the expiry scheduler share this resolution."""

    def test_team_policy_participates(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, max_key_days=30)
        assert policy_mod.max_key_days(db, team, reg) == 30

    def test_shortest_lifetime_wins(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, max_key_days=90)
        _policy(db, "registry", reg.id, max_key_days=7)
        assert policy_mod.max_key_days(db, team, reg) == 7

    def test_registry_cannot_extend_a_team_lifetime(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id, max_key_days=7)
        _policy(db, "registry", reg.id, max_key_days=365)
        assert policy_mod.max_key_days(db, team, reg) == 7

    def test_no_policy_means_no_expiry(self, db, pair):
        team, reg = pair
        assert policy_mod.max_key_days(db, team, reg) is None


class TestNullMeansNoOpinion:

    def test_a_policy_row_with_empty_fields_changes_nothing(self, db, pair):
        team, reg = pair
        _policy(db, "team", team.id)  # every field null
        eff = policy_mod.resolve(db, team, reg, global_cn_required=True, global_rate_limit_rpm=60)
        assert eff.ip_allowlists == []
        assert eff.hour_windows == []
        assert eff.cn_required is True
        assert eff.rate_limit_rpm == 60
        assert eff.max_key_days is None
