"""
Secret-leakage invariants.

Aegis makes two promises that are easy to state and easy to break by accident:

  1. Nothing derived from an upstream provider's response reaches the caller,
     the audit log, or a SIEM sink. CyberArk and Conjur return the password as
     the raw response body, so an error path that echoes the body is one
     upstream misbehaviour away from handing a credential to whoever asked.

  2. A rotated API key is delivered to the subscriber once and is not written
     down. It used to survive in webhook_log.payload, which made every
     historical key recoverable by anyone who could read that table.

Both are tested here by pushing a sentinel through the system and asserting it
does not appear in any sink, rather than by checking the shape of one function.

Requires PostgreSQL (aegis_test).
"""
import json
import uuid

import pytest

from aegis import errors, webhook
from aegis.models import (
    AuditLog,
    Object,
    Registry,
    RegistryObject,
    Team,
    Webhook,
    WebhookLog,
)
from tests.conftest import ADMIN_CREDS

# Distinctive enough that a substring match cannot be a coincidence.
SENTINEL = "SUPER-SECRET-SENTINEL-d3f4b1c2"


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _scenario(db, client):
    obj = Object(name=_unique("obj"), vendor="cyberark", auth_ref="prod",
                 path="secret/test", created_by="test")
    reg = Registry(name=_unique("reg"), created_by="test")
    db.add(obj)
    db.add(reg)
    db.flush()
    db.add(RegistryObject(registry_id=reg.id, object_name=obj.name))
    team = Team(name=_unique("team"), created_by="test")
    db.add(team)
    db.commit()
    resp = client.post(f"/admin/api/teams/{team.id}/registries/{reg.id}", auth=ADMIN_CREDS)
    assert resp.status_code == 201, resp.text
    return obj, reg, team, resp.json()["new_key"]["key"]


class TestUpstreamErrorsDoNotLeak:
    """An upstream failure must not carry the provider's response anywhere."""

    def test_vendor_error_reaches_neither_response_nor_audit(self, client, db, monkeypatch, caplog):
        obj, reg, team, key = _scenario(db, client)

        def explode(rows, auth):
            # What a misbehaving proxy or an error page can contain: on the
            # CyberArk success path this same field *is* the password.
            raise errors.UpstreamError("cyberark", "GET", 500)

        monkeypatch.setattr("aegis.deps.fetch_secrets", explode)
        with caplog.at_level("ERROR"):
            resp = client.get("/secrets", headers={"Authorization": f"Bearer {key}",
                                                   "X-Change-Number": "CHG-1"})

        assert resp.status_code == 502
        assert resp.json()["detail"] == errors.PUBLIC_UPSTREAM_MESSAGE
        # Useful without being revealing.
        row = (db.query(AuditLog)
                 .filter(AuditLog.registry_name == reg.name, AuditLog.outcome == "error")
                 .order_by(AuditLog.id.desc()).first())
        assert row is not None
        assert "cyberark" in row.error_detail and "500" in row.error_detail

    def test_response_body_in_an_exception_never_escapes(self, client, db, monkeypatch, caplog):
        obj, reg, team, key = _scenario(db, client)

        def explode(rows, auth):
            # A vendor adapter that has not been sanitised, or any third-party
            # library raising with the body embedded.
            raise ValueError(f"upstream said: {SENTINEL}")

        monkeypatch.setattr("aegis.deps.fetch_secrets", explode)
        with caplog.at_level("ERROR"):
            resp = client.get("/secrets", headers={"Authorization": f"Bearer {key}",
                                                   "X-Change-Number": "CHG-2"})

        assert resp.status_code == 502
        assert SENTINEL not in resp.text
        row = (db.query(AuditLog)
                 .filter(AuditLog.registry_name == reg.name, AuditLog.outcome == "error")
                 .order_by(AuditLog.id.desc()).first())
        assert SENTINEL not in (row.error_detail or "")
        assert SENTINEL not in caplog.text

    def test_upstream_error_carries_no_body(self):
        exc = errors.UpstreamError("vault", "GET", 403)
        assert "vault" in exc.audit_detail and "403" in exc.audit_detail
        assert exc.public_message == errors.PUBLIC_UPSTREAM_MESSAGE

    def test_safe_detail_of_an_arbitrary_exception_is_only_its_type(self):
        assert errors.safe_detail(ValueError(SENTINEL)) == "ValueError"
        assert SENTINEL not in errors.safe_detail(RuntimeError(SENTINEL))


class TestRotatedKeyIsNotPersisted:
    """The plaintext key goes to the subscriber, not into webhook_log."""

    def test_delivery_record_is_redacted_but_the_request_body_is_not(self, db, monkeypatch):
        # Broadcasting the key is opt-in; this test is about what happens to
        # the delivery record when a deployment has opted in.
        monkeypatch.setenv("WEBHOOK_INCLUDE_ROTATED_KEY", "true")
        team = Team(name=_unique("team"), created_by="test")
        db.add(team)
        db.commit()

        hook = Webhook(team_id=team.id, url="https://example.test/hook", signing_secret="s3cret",
                       signing_enabled=False, events=["key.rotated"], enabled=True)
        db.add(hook)
        db.commit()

        sent = {}

        class Resp:
            status_code = 200
            text = "ok"

        # Delivery goes through url_guard.request (SSRF validation + DNS
        # pinning), not requests directly.
        def fake_request(method, url, **kwargs):
            sent["body"] = kwargs.get("data") or kwargs.get("json")
            return Resp()

        monkeypatch.setattr("aegis.url_guard.request", fake_request)
        monkeypatch.setattr("aegis.url_guard.check_url", lambda url: None)

        payload = webhook.build_payload(
            "key.rotated", {"id": str(team.id), "name": team.name},
            registry={"id": "r", "name": "reg"},
            new_key=SENTINEL, key_preview="sk_abcd...", reason="manual_rotation")
        webhook.deliver(db, hook, "key.rotated", payload)
        db.commit()

        # The subscriber still receives the key - that is the point of the event.
        assert SENTINEL in str(sent["body"])

        log = (db.query(WebhookLog)
                 .filter(WebhookLog.team_id == team.id)
                 .order_by(WebhookLog.id.desc()).first())
        assert log is not None
        assert SENTINEL not in log.payload
        stored = json.loads(log.payload)
        assert stored["new_key"] == errors.REDACTED
        # Enough left to correlate the delivery with the key it rotated.
        assert stored["key_preview"] == "sk_abcd..."
        assert stored["event"] == "key.rotated"

    def test_blocked_delivery_is_also_redacted(self, db, monkeypatch):
        monkeypatch.setenv("WEBHOOK_INCLUDE_ROTATED_KEY", "true")
        team = Team(name=_unique("team"), created_by="test")
        db.add(team)
        db.commit()
        hook = Webhook(team_id=team.id, url="http://169.254.169.254/", signing_secret=None,
                       signing_enabled=False, events=["key.rotated"], enabled=True)
        db.add(hook)
        db.commit()

        monkeypatch.setattr("aegis.url_guard.check_url", lambda url: "link-local address")
        payload = webhook.build_payload("key.rotated", {"id": str(team.id), "name": team.name},
                                        new_key=SENTINEL, key_preview="sk_abcd...")
        webhook.deliver(db, hook, "key.rotated", payload)
        db.commit()

        log = (db.query(WebhookLog)
                 .filter(WebhookLog.team_id == team.id)
                 .order_by(WebhookLog.id.desc()).first())
        assert log is not None and log.success is False
        assert SENTINEL not in log.payload


class TestRedaction:

    def test_sensitive_keys_are_replaced(self):
        out = errors.redact({"new_key": SENTINEL, "password": "p", "token": "t",
                             "key_preview": "sk_ab...", "event": "key.rotated"})
        assert out["new_key"] == errors.REDACTED
        assert out["password"] == errors.REDACTED
        assert out["token"] == errors.REDACTED
        # Non-sensitive fields survive untouched.
        assert out["key_preview"] == "sk_ab..."
        assert out["event"] == "key.rotated"

    def test_absent_values_are_not_marked_redacted(self):
        # A non-rotation event carries new_key=None; claiming it was redacted
        # would be misleading in the delivery record.
        assert errors.redact({"new_key": None})["new_key"] is None

    def test_nested_structures_are_walked(self):
        out = errors.redact({"team": {"api_key": SENTINEL},
                             "items": [{"secret": SENTINEL}, {"name": "ok"}]})
        assert out["team"]["api_key"] == errors.REDACTED
        assert out["items"][0]["secret"] == errors.REDACTED
        assert out["items"][1]["name"] == "ok"

    def test_sentinel_cannot_survive_serialisation(self):
        payload = webhook.build_payload("key.rotated", {"id": "t", "name": "t"},
                                        new_key=SENTINEL, key_preview="sk_ab...")
        assert SENTINEL not in json.dumps(errors.redact(payload), default=str)


@pytest.mark.parametrize("field", sorted(errors.SENSITIVE_KEYS))
def test_every_declared_sensitive_key_is_actually_redacted(field):
    assert errors.redact({field: SENTINEL})[field] == errors.REDACTED
