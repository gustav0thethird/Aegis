"""
Webhook delivery must not run inside the request.

deliver() sleeps between retries (0s, 5s, 30s) around attempts that each allow
10s, and notify_channels() adds three more outbound calls. Firing an event
inline therefore added up to about a minute and a half to a response - and
policy violations fire an event, so anyone who could trigger a 403 could make
the service spend a worker on their behalf.

These tests assert the timing property directly rather than inspecting the
implementation: a request that fires an event must return while delivery is
still in progress.

Requires PostgreSQL (aegis_test).
"""
import threading
import time
import uuid

import pytest

from aegis import webhook
from aegis.models import Team, Webhook


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def team_with_webhook(db, _schema):
    team = Team(name=_unique("team"), created_by="test")
    db.add(team)
    db.commit()
    hook = Webhook(team_id=team.id, url="https://example.test/hook", secret=None,
                   signing_enabled=False, events=["policy.violated", "key.rotated"],
                   enabled=True)
    db.add(hook)
    db.commit()
    db.refresh(team)
    yield team, hook
    db.query(Webhook).filter(Webhook.team_id == team.id).delete()
    db.delete(team)
    db.commit()


@pytest.fixture
def background_mode(monkeypatch):
    """conftest forces sync for determinism; these tests want the default."""
    monkeypatch.setenv("WEBHOOK_DISPATCH_MODE", "background")


class TestDispatchIsOffTheRequestPath:

    def test_fire_returns_before_a_slow_delivery_finishes(
            self, db, team_with_webhook, background_mode, monkeypatch):
        team, _ = team_with_webhook
        started = threading.Event()
        release = threading.Event()

        def slow_request(method, url, **kwargs):
            started.set()
            release.wait(timeout=10)
            raise ConnectionError("still hanging")

        monkeypatch.setattr("aegis.url_guard.request", slow_request)
        monkeypatch.setattr("aegis.url_guard.check_url", lambda url: None)
        # No real waiting between retries in this test.
        monkeypatch.setattr(webhook, "RETRY_BACKOFF", [0])

        begin = time.monotonic()
        webhook.fire(db, team, "policy.violated", detail="blocked")
        elapsed = time.monotonic() - begin

        # The caller is not waiting on the network.
        assert elapsed < 1.0, f"fire() blocked for {elapsed:.2f}s"
        assert started.wait(timeout=5), "delivery never started in the background"
        release.set()

    def test_sync_mode_does_wait(self, db, team_with_webhook, monkeypatch):
        """Opt-in for deployments that would rather fail than miss an event."""
        team, _ = team_with_webhook
        monkeypatch.setenv("WEBHOOK_DISPATCH_MODE", "sync")
        calls = []

        def slow_request(method, url, **kwargs):
            calls.append(url)
            raise ConnectionError("unreachable")

        monkeypatch.setattr("aegis.url_guard.request", slow_request)
        monkeypatch.setattr("aegis.url_guard.check_url", lambda url: None)
        monkeypatch.setattr(webhook, "RETRY_BACKOFF", [0])

        webhook.fire(db, team, "policy.violated", detail="blocked")
        # Delivery has already been attempted by the time fire() returns.
        assert calls

    def test_nothing_configured_queues_nothing(self, db, _schema, background_mode, monkeypatch):
        team = Team(name=_unique("team"), created_by="test")
        db.add(team)
        db.commit()
        submitted = []
        monkeypatch.setattr(webhook, "_executor",
                            lambda: type("E", (), {"submit": lambda self, *a, **k: submitted.append(a)})())
        webhook.fire(db, team, "policy.violated", detail="x")
        assert submitted == []
        db.delete(team)
        db.commit()

    def test_background_delivery_is_recorded(self, db, team_with_webhook, background_mode, monkeypatch):
        """The worker opens its own session; the delivery still lands in webhook_log."""
        from aegis.models import WebhookLog

        team, hook = team_with_webhook
        done = threading.Event()

        class Resp:
            status_code = 200
            ok = True
            text = "ok"

        def ok_request(method, url, **kwargs):
            done.set()
            return Resp()

        monkeypatch.setattr("aegis.url_guard.request", ok_request)
        monkeypatch.setattr("aegis.url_guard.check_url", lambda url: None)

        webhook.fire(db, team, "key.rotated", new_key="k", key_preview="sk_ab...")
        assert done.wait(timeout=10), "delivery never ran"

        # The worker committed in its own session, so this one has to look again.
        deadline = time.monotonic() + 10
        row = None
        while time.monotonic() < deadline and row is None:
            db.rollback()
            row = (db.query(WebhookLog)
                     .filter(WebhookLog.team_id == team.id)
                     .order_by(WebhookLog.id.desc()).first())
            if row is None:
                time.sleep(0.2)
        assert row is not None, "background delivery was not logged"
        assert row.success is True
        # Redaction still applies on the background path.
        assert '"new_key": "[redacted]"' in row.payload
