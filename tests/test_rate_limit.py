"""
Unit tests for the Redis sliding-window rate limiter.
Uses FakeRedis — no real Redis required.
"""

import pytest
import fakeredis
import redis as redis_lib

from aegis import rate_limit


@pytest.fixture(autouse=True)
def isolated_redis():
    """Give each test its own FakeRedis instance."""
    r = fakeredis.FakeRedis(decode_responses=True)
    rate_limit._client = r
    yield r
    rate_limit._client = None


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
        """Redis failure must fail open (allow the request) to avoid a hard outage."""
        def broken():
            raise redis_lib.RedisError("connection refused")

        monkeypatch.setattr(rate_limit, "_redis_client", broken)

        allowed, remaining = rate_limit.check("key7", rpm=10)
        assert allowed is True
        assert remaining == 10
