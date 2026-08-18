"""
Unit tests for the Redis sliding-window rate limiter.
Uses FakeRedis — no real Redis required.
"""

import fakeredis
import pytest
import redis as redis_lib

from aegis import rate_limit


@pytest.fixture(autouse=True)
def isolated_redis():
    """
    Give each test its own FakeRedis instance.

    Restores whatever was installed before rather than blanking the client — the
    session-scoped `client` fixture installs its own FakeRedis, and clearing it
    here left later tests talking to a Redis that isn't there.
    """
    previous = rate_limit._client
    r = fakeredis.FakeRedis(decode_responses=True)
    rate_limit._client = r
    yield r
    rate_limit._client = previous


class TestRateLimitCheck:
    def test_first_request_is_allowed(self):
        allowed, remaining = rate_limit.check("key1", rpm=10)
        assert allowed is True
        assert remaining == 9

    def test_remaining_decrements(self):
        rate_limit.check("key2", rpm=5)
        rate_limit.check("key2", rpm=5)
        _, remaining = rate_limit.check("key2", rpm=5)
        assert remaining == 2

    def test_request_at_limit_is_still_allowed(self):
        # The limit-th request should be allowed (count == limit)
        for _ in range(9):
            rate_limit.check("key3", rpm=10)
        allowed, remaining = rate_limit.check("key3", rpm=10)
        assert allowed is True
        assert remaining == 0

    def test_request_over_limit_is_denied(self):
        for _ in range(10):
            rate_limit.check("key4", rpm=10)
        allowed, remaining = rate_limit.check("key4", rpm=10)
        assert allowed is False
        assert remaining == 0

    def test_different_keys_are_independent(self):
        for _ in range(10):
            rate_limit.check("key5", rpm=10)
        # Exhausted key5, but key6 should be untouched
        allowed, _ = rate_limit.check("key6", rpm=10)
        assert allowed is True

    def test_fail_open_when_redis_is_unavailable(self, monkeypatch):
        """Redis failure defaults to failing open (allow) to avoid a hard outage."""
        def broken():
            raise redis_lib.RedisError("connection refused")

        monkeypatch.setattr(rate_limit, "_redis_client", broken)

        allowed, remaining = rate_limit.check("key7", rpm=10)
        assert allowed is True
        assert remaining == 10


class TestFailMode:
    """The availability/security trade-off on Redis outage is deployment policy."""

    @pytest.fixture(autouse=True)
    def broken_redis(self, monkeypatch):
        def broken():
            raise redis_lib.RedisError("connection refused")

        monkeypatch.setattr(rate_limit, "_redis_client", broken)

    def test_defaults_to_fail_open(self, monkeypatch):
        monkeypatch.delenv("RATE_LIMIT_FAIL_MODE", raising=False)
        assert rate_limit.check("fm1", rpm=10) == (True, 10)

    def test_explicit_open_allows(self, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "open")
        assert rate_limit.check("fm2", rpm=10) == (True, 10)

    def test_closed_denies(self, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "closed")
        assert rate_limit.check("fm3", rpm=10) == (False, 0)

    def test_mode_is_case_and_whitespace_insensitive(self, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "  CLOSED  ")
        assert rate_limit.check("fm4", rpm=10) == (False, 0)

    def test_unrecognised_mode_falls_back_to_open(self, monkeypatch):
        """An unreadable setting must not silently turn into an outage."""
        monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "banana")
        assert rate_limit.check("fm5", rpm=10) == (True, 10)

    def test_mode_is_read_per_call(self, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "closed")
        assert rate_limit.check("fm6", rpm=10)[0] is False
        monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "open")
        assert rate_limit.check("fm6", rpm=10)[0] is True
