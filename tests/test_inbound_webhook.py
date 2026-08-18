"""
Integration tests for the inbound webhook receiver (POST /api/inbound/{team_id}).

Requires PostgreSQL (aegis_test).

Focus: the rotate_key action must mint keys in the same format as every other
rotation path, so that downstream consumers parsing the `sk_` prefix cannot tell
where a key came from.
"""

import hashlib
import secrets as slib

from aegis.models import Registry, Team, TeamRegistry, TeamRegistryKey, Webhook


def _unique(prefix):
    return f"{prefix}_{slib.token_hex(4)}"


def _scenario(db):
    """Team with an inbound-capable webhook, plus a registry it may rotate."""
    team = Team(name=_unique("team"), created_by="test")
    reg = Registry(name=_unique("reg"), created_by="test")
    db.add(team)
    db.add(reg)
    db.flush()

    db.add(TeamRegistry(team_id=team.id, registry_id=reg.id, assigned_by="test"))

    secret = slib.token_hex(16)
    db.add(Webhook(
        team_id=team.id,
        url="https://hooks.example.com/aegis",
        events=["key.rotated"],
        enabled=False,           # outbound delivery off — this test is about the key
        signing_enabled=True,
        secret=secret,
        created_by="test",
    ))
    db.commit()
    return team, reg, secret


def _rotate(client, team, reg, secret):
    return client.post(
        f"/api/inbound/{team.id}",
        headers={"Authorization": f"Bearer {secret}"},
        json={"action": "rotate_key", "registry_id": str(reg.id)},
    )


class TestInboundRotateKey:

    def test_rotated_key_uses_the_project_key_format(self, client, db):
        """Regression: this path used a bare token_urlsafe(40) with no sk_ prefix."""
        team, reg, secret = _scenario(db)
        resp = _rotate(client, team, reg, secret)

        assert resp.status_code == 200, resp.text
        assert resp.json()["new_key"].startswith("sk_")

    def test_preview_matches_the_shared_convention(self, client, db):
        team, reg, secret = _scenario(db)
        body = _rotate(client, team, reg, secret).json()

        assert body["key_preview"] == body["new_key"][:10] + "..."

    def test_stored_hash_and_preview_match_the_returned_key(self, client, db):
        team, reg, secret = _scenario(db)
        body = _rotate(client, team, reg, secret).json()

        row = db.query(TeamRegistryKey).filter(
            TeamRegistryKey.team_id == team.id,
            TeamRegistryKey.registry_id == reg.id,
            TeamRegistryKey.revoked_at.is_(None),
        ).one()

        assert row.key_hash == hashlib.sha256(body["new_key"].encode()).hexdigest()
        assert row.key_preview == body["key_preview"]

    def test_previous_key_is_revoked(self, client, db):
        team, reg, secret = _scenario(db)
        first = _rotate(client, team, reg, secret).json()["new_key"]
        second = _rotate(client, team, reg, secret).json()["new_key"]

        assert first != second
        active = db.query(TeamRegistryKey).filter(
            TeamRegistryKey.team_id == team.id,
            TeamRegistryKey.registry_id == reg.id,
            TeamRegistryKey.revoked_at.is_(None),
        ).all()
        assert len(active) == 1

    def test_bad_token_is_rejected(self, client, db):
        team, reg, _ = _scenario(db)
        resp = _rotate(client, team, reg, "not-the-secret")
        assert resp.status_code == 403

    def test_ping_action_still_works(self, client, db):
        team, _, secret = _scenario(db)
        resp = client.post(
            f"/api/inbound/{team.id}",
            headers={"Authorization": f"Bearer {secret}"},
            json={"action": "ping"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
