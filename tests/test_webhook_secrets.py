"""
The inbound token and the outbound signing secret are separate credentials.

One column held one value doing both jobs, in the clear:

  * it authenticated POST /api/inbound/{team_id}, which can rotate a team's
    API key and returns the new key in its response;
  * it was the HMAC key for signing outbound deliveries.

So reading the webhooks table was enough to rotate a key, receive it, and
fetch every secret in the registry. A database read became access to the
secrets themselves.

They are now distinct. Only the hash of the inbound token is stored, so it
cannot be recovered from a row. The signing secret must remain recoverable -
HMAC needs the key - but on its own it only permits forging events to the
team's own endpoint.

Requires PostgreSQL (aegis_test).
"""
import hashlib
import uuid

import pytest

from aegis.models import Team, Webhook
from tests.conftest import ADMIN_CREDS


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def team_hook(db, _schema):
    team = Team(name=_unique("team"), created_by="test")
    db.add(team)
    db.commit()
    hook = Webhook(team_id=team.id, url="https://example.test/hook",
                   signing_enabled=True, signing_secret="signing-key-value",
                   events=["key.rotated"], enabled=True, created_by="test")
    db.add(hook)
    db.commit()
    db.refresh(team)
    yield team, hook
    db.query(Webhook).filter(Webhook.team_id == team.id).delete()
    db.delete(team)
    db.commit()


def _set_inbound(db, hook, token):
    hook.inbound_secret_hash = hashlib.sha256(token.encode()).hexdigest()
    db.commit()


class TestInboundTokenIsNotRecoverable:

    def test_only_the_hash_is_stored(self, db, team_hook):
        _team, hook = team_hook
        token = "inbound-token-value-abc123"
        _set_inbound(db, hook, token)
        db.refresh(hook)
        assert hook.inbound_secret_hash == hashlib.sha256(token.encode()).hexdigest()
        # The column that used to hold it in the clear is gone.
        assert not hasattr(hook, "secret")

    def test_the_signing_secret_is_not_the_inbound_token(self, db, team_hook):
        """
        The point of the split. While they were one value, reading the
        signing secret was enough to call the inbound endpoint.
        """
        _team, hook = team_hook
        _set_inbound(db, hook, "inbound-token-value-abc123")
        db.refresh(hook)
        assert hook.signing_secret == "signing-key-value"
        assert hook.signing_secret != hook.inbound_secret_hash
        assert (hashlib.sha256(hook.signing_secret.encode()).hexdigest()
                != hook.inbound_secret_hash), "signing secret still authenticates inbound"


class TestInboundAuthentication:

    def _post(self, client, team, token, action="rotate_key"):
        return client.post(f"/api/inbound/{team.id}",
                           headers={"Authorization": f"Bearer {token}"},
                           json={"action": action})

    def test_the_correct_token_is_accepted(self, client, db, team_hook, monkeypatch):
        team, hook = team_hook
        token = "inbound-token-value-abc123"
        _set_inbound(db, hook, token)
        # rotate_key needs a registry assignment; a 403 for "no access" still
        # proves authentication succeeded, which is what this asserts.
        resp = self._post(client, team, token)
        assert resp.status_code != 403 or "token" not in resp.json()["detail"].lower()

    def test_the_signing_secret_is_rejected(self, client, db, team_hook):
        """Previously the same value, so this would have authenticated."""
        team, hook = team_hook
        _set_inbound(db, hook, "inbound-token-value-abc123")
        resp = self._post(client, team, "signing-key-value")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Invalid token"

    def test_a_wrong_token_is_rejected(self, client, db, team_hook):
        team, hook = team_hook
        _set_inbound(db, hook, "inbound-token-value-abc123")
        assert self._post(client, team, "not-the-token").status_code == 403

    def test_no_inbound_token_configured_is_rejected(self, client, db, team_hook):
        team, hook = team_hook
        hook.inbound_secret_hash = None
        db.commit()
        resp = self._post(client, team, "anything")
        assert resp.status_code == 403
        assert "no inbound token" in resp.json()["detail"].lower()

    def test_inbound_does_not_depend_on_outbound_signing(self, client, db, team_hook):
        """
        Inbound used to be gated on signing_enabled, because the two shared a
        value. Turning off outbound signing must not silently disable a team's
        CI integration.
        """
        team, hook = team_hook
        _set_inbound(db, hook, "inbound-token-value-abc123")
        hook.signing_enabled = False
        hook.signing_secret = None
        db.commit()
        resp = self._post(client, team, "inbound-token-value-abc123")
        assert resp.status_code != 403 or "not configured" not in resp.json()["detail"].lower()


class TestApiNeverReturnsEitherCredential:

    def test_admin_webhook_response_reports_presence_only(self, client, db, team_hook):
        team, hook = team_hook
        _set_inbound(db, hook, "inbound-token-value-abc123")
        body = client.get(f"/admin/api/teams/{team.id}/webhook", auth=ADMIN_CREDS).json()
        assert body["has_signing_secret"] is True
        assert body["has_inbound_token"] is True
        blob = str(body)
        assert "signing-key-value" not in blob
        assert "inbound-token-value-abc123" not in blob
        assert hook.inbound_secret_hash not in blob

    def test_rotating_the_inbound_token_returns_it_once(self, client, db, team_hook):
        team, _hook = team_hook
        resp = client.post(f"/admin/api/teams/{team.id}/webhook/rotate-inbound-token",
                           auth=ADMIN_CREDS)
        assert resp.status_code == 200
        token = resp.json()["inbound_token"]
        assert token

        # Stored as a hash, so it cannot be read back.
        db.expire_all()
        hook = db.query(Webhook).filter(Webhook.team_id == team.id).one()
        assert hook.inbound_secret_hash == hashlib.sha256(token.encode()).hexdigest()
        body = client.get(f"/admin/api/teams/{team.id}/webhook", auth=ADMIN_CREDS).json()
        assert token not in str(body)

    def test_a_rotated_token_authenticates_and_the_old_one_stops(self, client, db, team_hook):
        team, hook = team_hook
        _set_inbound(db, hook, "old-inbound-token")
        new = client.post(f"/admin/api/teams/{team.id}/webhook/rotate-inbound-token",
                          auth=ADMIN_CREDS).json()["inbound_token"]

        old_resp = client.post(f"/api/inbound/{team.id}",
                               headers={"Authorization": "Bearer old-inbound-token"},
                               json={"action": "rotate_key"})
        assert old_resp.status_code == 403

        new_resp = client.post(f"/api/inbound/{team.id}",
                               headers={"Authorization": f"Bearer {new}"},
                               json={"action": "rotate_key"})
        assert new_resp.status_code != 403 or "token" not in new_resp.json()["detail"].lower()


class TestOutboundSigningStillWorks:

    def test_deliveries_are_signed_with_the_signing_secret(self, db, team_hook, monkeypatch):
        import hmac

        from aegis import webhook as wh

        team, hook = team_hook
        sent = {}

        class Resp:
            status_code = 200
            ok = True
            text = "ok"

        def capture(method, url, **kwargs):
            sent["body"] = kwargs.get("data")
            sent["headers"] = kwargs.get("headers") or {}
            return Resp()

        monkeypatch.setenv("WEBHOOK_DISPATCH_MODE", "sync")
        monkeypatch.setattr("aegis.url_guard.request", capture)
        monkeypatch.setattr("aegis.url_guard.check_url", lambda url: None)

        wh.fire(db, team, "key.rotated", key_preview="sk_ab...")
        db.commit()

        signature = sent["headers"].get("X-Aegis-Signature")
        assert signature, "delivery was not signed"
        digest = hmac.new(b"signing-key-value", sent["body"].encode(), "sha256").hexdigest()
        # The header is prefixed with the algorithm, as the receiver expects.
        assert signature == f"sha256={digest}"
