"""
rate_limit.py — Redis sliding-window rate limiter.

One counter per (key_id, minute_bucket). Each counter has a 60s TTL so
they expire automatically without a cleanup job.

Config:
  REDIS_URL       — redis://host:6379  (default: redis://localhost:6379)
  RATE_LIMIT_RPM  — requests per minute per key (default: 60)
"""

import os
import time
import logging
import redis

logger = logging.getLogger("aegis.rate_limit")

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
_RPM       = int(os.environ.get("RATE_LIMIT_RPM", "60"))

_client: redis.Redis | None = None


def _redis_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(_REDIS_URL, decode_responses=True, socket_timeout=1)
    return _client


# Keep old name for backwards compat
def _get_client() -> redis.Redis:
    return _redis_client()


def check(key_id: str, rpm: int | None = None) -> tuple[bool, int]:
    """
    Check and increment the rate counter for key_id.

    Returns (allowed, remaining):
      allowed   — True if the request is within the rate limit
      remaining — requests remaining in the current minute window
    """
    bucket = int(time.time() // 60)
    redis_key = f"rate:{key_id}:{bucket}"

    limit = rpm if rpm is not None else _RPM
    try:
        client = _redis_client()
        pipe = client.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, 60)
        count, _ = pipe.execute()

        remaining = max(0, limit - count)
        allowed   = count <= limit
        return allowed, remaining

    except redis.RedisError as exc:
        # Redis unavailable — fail open with a warning rather than blocking all requests
        logger.warning("Redis rate limit check failed (failing open): %s", exc)
        return True, limit
