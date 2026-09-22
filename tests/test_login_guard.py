"""
Login brute-force protection and session management.

/api/login had no limiter, so an exposed instance could be sprayed with
password guesses, each costing a bcrypt verification.

The session tests exist because admin_list_sessions called .decode() on keys
from a client configured with decode_responses=True, so listing sessions threw
AttributeError inside a per-session try block and silently returned nothing.
Nothing caught it, because nothing tested it end to end.

Requires PostgreSQL (aegis_test) and the FakeRedis fixture.
"""
import uuid

import pytest

from aegis import login_guard, rate_limit
from aegis.deps import _hash_pw
from aegis.models import User
from tests.conftest import ADMIN_CREDS


@pytest.fixture(autouse=True)
def _clear_login_counters():
    """Counters are shared state; start each test from a clean slate."""
    try:
        client = rate_limit._redis_client()
        for key in list(client.scan_iter("login:fail:*")):
            client.delete(key)
    except Exception:
        pass
    yield


@pytest.fixture
def user(db):
    u = User(username=f"guard-{uuid.uuid4().hex[:8]}", password_hash=_hash_pw("correct-horse"),
             role="user", theme="default", created_by="test")
    db.add(u)
    db.commit()
    yield u
    db.delete(u)
    db.commit()


class TestLoginGuard:

    def test_correct_password_succeeds(self, client, user):
        resp = client.post("/api/login", json={"username": user.username, "password": "correct-horse"})
        assert resp.status_code == 200
        assert resp.json()["username"] == user.username

    def test_repeated_failures_are_locked_out(self, client, user):
        for _ in range(login_guard.USER_MAX_FAILURES):
            resp = client.post("/api/login", json={"username": user.username, "password": "wrong"})
            assert resp.status_code == 401

        # The next attempt is not evaluated at all.
        resp = client.post("/api/login", json={"username": user.username, "password": "wrong"})
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert int(resp.headers["Retry-After"]) > 0

    def test_lockout_applies_even_to_the_correct_password(self, client, user):
        """Otherwise an attacker learns they found it by the response changing."""
        for _ in range(login_guard.USER_MAX_FAILURES):
            client.post("/api/login", json={"username": user.username, "password": "wrong"})
        resp = client.post("/api/login", json={"username": user.username, "password": "correct-horse"})
        assert resp.status_code == 429

    def test_success_clears_the_counter(self, client, user):
        for _ in range(login_guard.USER_MAX_FAILURES - 1):
            client.post("/api/login", json={"username": user.username, "password": "wrong"})
        assert client.post("/api/login",
                           json={"username": user.username, "password": "correct-horse"}).status_code == 200
        # Back to a full allowance rather than one attempt from a lock.
        for _ in range(login_guard.USER_MAX_FAILURES - 1):
            assert client.post("/api/login",
                               json={"username": user.username, "password": "wrong"}).status_code == 401

    def test_unknown_user_is_indistinguishable_from_a_wrong_password(self, client, user):
        missing = client.post("/api/login", json={"username": "no-such-user", "password": "x"})
        wrong = client.post("/api/login", json={"username": user.username, "password": "x"})
        assert missing.status_code == wrong.status_code == 401
        assert missing.json() == wrong.json()

    def test_failures_for_an_unknown_user_still_count(self, client):
        """Otherwise guessing usernames is unlimited."""
        name = f"nobody-{uuid.uuid4().hex[:6]}"
        for _ in range(login_guard.USER_MAX_FAILURES):
            assert client.post("/api/login", json={"username": name, "password": "x"}).status_code == 401
        assert client.post("/api/login", json={"username": name, "password": "x"}).status_code == 429

    def test_guard_allows_when_redis_is_unavailable(self, client, user, monkeypatch):
        """A login endpoint that fails closed when its cache is down is an outage."""
        def boom():
            raise ConnectionError("redis down")
        monkeypatch.setattr("aegis.rate_limit._redis_client", boom)
        allowed, retry = login_guard.check("1.2.3.4", "someone")
        assert allowed is True and retry == 0

    def test_lock_duration_backs_off(self):
        first = login_guard._lock_seconds(login_guard.USER_MAX_FAILURES, login_guard.USER_MAX_FAILURES)
        later = login_guard._lock_seconds(login_guard.USER_MAX_FAILURES + 3, login_guard.USER_MAX_FAILURES)
        assert later > first
        assert later <= login_guard.MAX_LOCK_SECONDS


class TestSessionManagement:
    """The end-to-end coverage the .decode() bug slipped through."""

    def test_session_appears_in_the_listing_and_can_be_revoked(self, client, user):
        login = client.post("/api/login", json={"username": user.username, "password": "correct-horse"})
        assert login.status_code == 200
        token = login.json()["token"]

        listing = client.get("/admin/api/sessions", auth=ADMIN_CREDS)
        assert listing.status_code == 200
        rows = listing.json()["sessions"]
        mine = [r for r in rows if r["username"] == user.username]
        assert mine, f"session for {user.username} missing from {rows}"
        assert mine[0]["token_preview"].endswith("...")
        assert mine[0]["token_key"].startswith("aegis:session:")

        # The session works before revocation and not after.
        assert client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
        revoke = client.delete(f"/admin/api/sessions/{mine[0]['token_key']}", auth=ADMIN_CREDS)
        assert revoke.status_code in (200, 204), revoke.text
        assert client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

        after = client.get("/admin/api/sessions", auth=ADMIN_CREDS).json()["sessions"]
        assert not [r for r in after if r["username"] == user.username]
