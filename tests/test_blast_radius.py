"""
Defaults that decide how far a single compromise reaches.

Two settings shipped permissive and are now opt-in. Both are tested here
because the safe behaviour is a default, and defaults are exactly what a
later refactor silently flips back.

  WEBHOOK_INCLUDE_ROTATED_KEY  a rotation event used to carry the plaintext
                               key to whatever URL a team configured, which
                               made the credential's trust boundary that
                               endpoint plus its proxy, logs and monitoring.

  ESO_ALLOW_REGISTRY_EXTRACT   one External Secrets Operator request could
                               return every object in a registry, so a single
                               consumer's credential reached the whole bundle.

Requires PostgreSQL (aegis_test).
"""
import json
import uuid

import pytest

from aegis import deps, errors, webhook
from aegis.models import Team, Webhook, WebhookLog

PLAINTEXT = "sk_rotated_plaintext_value_0001"


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class TestRotatedKeyIsNotBroadcast:

    def test_default_payload_omits_the_plaintext_key(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_INCLUDE_ROTATED_KEY", raising=False)
        payload = webhook.build_payload("key.rotated", {"id": "t", "name": "t"},
                                        new_key=PLAINTEXT, key_preview="sk_rota...")
        assert payload["new_key"] is None
        # A subscriber can still tell what happened and to which key.
        assert payload["key_preview"] == "sk_rota..."
        assert payload["event"] == "key.rotated"
        assert PLAINTEXT not in json.dumps(payload)

    def test_opt_in_restores_it(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_INCLUDE_ROTATED_KEY", "true")
        payload = webhook.build_payload("key.rotated", {"id": "t", "name": "t"},
                                        new_key=PLAINTEXT, key_preview="sk_rota...")
        assert payload["new_key"] == PLAINTEXT

    @pytest.mark.parametrize("value", ["false", "False", "0", "no", "", "yes"])
    def test_only_an_explicit_true_enables_it(self, monkeypatch, value):
        monkeypatch.setenv("WEBHOOK_INCLUDE_ROTATED_KEY", value)
        payload = webhook.build_payload("key.rotated", {"id": "t", "name": "t"},
                                        new_key=PLAINTEXT)
        assert payload["new_key"] is None

    def test_delivery_carries_no_key_and_logs_none(self, db, _schema, monkeypatch):
        """End to end: neither the request body nor the delivery record has it."""
        monkeypatch.delenv("WEBHOOK_INCLUDE_ROTATED_KEY", raising=False)
        monkeypatch.setenv("WEBHOOK_DISPATCH_MODE", "sync")

        team = Team(name=_unique("team"), created_by="test")
        db.add(team)
        db.commit()
        hook = Webhook(team_id=team.id, url="https://example.test/hook", signing_secret=None,
                       signing_enabled=False, events=["key.rotated"], enabled=True)
        db.add(hook)
        db.commit()
        db.refresh(team)

        sent = {}

        class Resp:
            status_code = 200
            ok = True
            text = "ok"

        def capture(method, url, **kwargs):
            sent["body"] = kwargs.get("data") or kwargs.get("json")
            return Resp()

        monkeypatch.setattr("aegis.url_guard.request", capture)
        monkeypatch.setattr("aegis.url_guard.check_url", lambda url: None)

        webhook.fire(db, team, "key.rotated", new_key=PLAINTEXT, key_preview="sk_rota...")
        db.commit()

        assert PLAINTEXT not in str(sent.get("body"))
        row = (db.query(WebhookLog).filter(WebhookLog.team_id == team.id)
                 .order_by(WebhookLog.id.desc()).first())
        assert row is not None
        assert PLAINTEXT not in row.payload

        db.query(WebhookLog).filter(WebhookLog.team_id == team.id).delete()
        db.query(Webhook).filter(Webhook.team_id == team.id).delete()
        db.delete(team)
        db.commit()

    def test_redaction_still_applies_when_opted_in(self, monkeypatch):
        """Belt and braces: even when broadcast is on, the log must not keep it."""
        monkeypatch.setenv("WEBHOOK_INCLUDE_ROTATED_KEY", "true")
        payload = webhook.build_payload("key.rotated", {"id": "t", "name": "t"},
                                        new_key=PLAINTEXT, key_preview="sk_rota...")
        assert PLAINTEXT not in json.dumps(errors.redact(payload))


class TestRegistryExtractIsOptIn:

    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("ESO_ALLOW_REGISTRY_EXTRACT", raising=False)
        assert deps._eso_registry_extract_allowed() is False

    def test_opt_in_enables_it(self, monkeypatch):
        monkeypatch.setenv("ESO_ALLOW_REGISTRY_EXTRACT", "true")
        assert deps._eso_registry_extract_allowed() is True

    @pytest.mark.parametrize("value", ["false", "False", "0", "no", "", "TRUE "])
    def test_anything_but_true_leaves_it_off(self, monkeypatch, value):
        monkeypatch.setenv("ESO_ALLOW_REGISTRY_EXTRACT", value)
        assert deps._eso_registry_extract_allowed() is (value.strip().lower() == "true")
