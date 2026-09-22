"""
Brute-force protection for password authentication.

/api/login was the one credential-checking endpoint with no limiter: the API
key path has had one from the start, but an internet-reachable instance could
be sprayed with password guesses, each costing a bcrypt verification. That is
both an online guessing attack and a cheap way to burn the service's CPU.

Two counters, because they defend against different things:

  user  - failures for one username from one address. Catches guessing against
          a known account. Locks quickly.
  ip    - failures from one address against any account. Catches spraying a
          common password across many usernames, which never trips the
          per-user counter.

Both are windowed counters in Redis rather than durable lockouts: an attacker
who stops is not punished forever, and a legitimate user is never permanently
locked out by someone else's traffic.

Failures are counted, successes clear the user counter. If Redis is
unreachable the guard allows the attempt - a login endpoint that fails closed
when its cache is down is an outage, not a security control - and says so in
the log, matching RATE_LIMIT_FAIL_MODE's default posture.
"""
from __future__ import annotations

import logging
import os

from aegis import rate_limit

logger = logging.getLogger("aegis.login_guard")

# Failures tolerated before the scope is locked, and how long the counter
# lives. Deliberately generous for humans, far below what a guessing attack
# needs to be useful.
USER_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "5"))
IP_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES_PER_IP", "25"))
WINDOW_SECONDS = int(os.environ.get("LOGIN_FAILURE_WINDOW_SECONDS", "900"))  # 15 min

# Lock length grows with how far past the threshold the scope is, so a
# persistent attacker backs off further each time while a user who mistypes
# twice more waits seconds.
BASE_LOCK_SECONDS = int(os.environ.get("LOGIN_LOCK_SECONDS", "60"))
MAX_LOCK_SECONDS = int(os.environ.get("LOGIN_MAX_LOCK_SECONDS", "900"))


def _key(scope: str, value: str) -> str:
    return f"login:fail:{scope}:{value}"


def _count(client, key: str) -> int:
    try:
        raw = client.get(key)
        return int(raw) if raw else 0
    except Exception:
        raise


def _lock_seconds(failures: int, threshold: int) -> int:
    """Doubling back-off from the first failure past the threshold."""
    over = max(0, failures - threshold)
    return min(MAX_LOCK_SECONDS, BASE_LOCK_SECONDS * (2 ** over))


def check(ip: str, username: str) -> tuple[bool, int]:
    """
    Whether a login attempt may proceed.

    Returns (allowed, retry_after_seconds). retry_after is 0 when allowed.
    """
    try:
        client = rate_limit._redis_client()
        for scope, value, threshold in (("user", f"{ip}:{username}", USER_MAX_FAILURES),
                                        ("ip", ip, IP_MAX_FAILURES)):
            failures = _count(client, _key(scope, value))
            if failures >= threshold:
                retry_after = _lock_seconds(failures, threshold)
                logger.warning("Login blocked scope=%s failures=%d retry_after=%ds",
                               scope, failures, retry_after)
                return False, retry_after
        return True, 0
    except Exception as exc:
        # Availability over enforcement, as with the request rate limiter.
        logger.error("Login guard unavailable, allowing attempt: %s", type(exc).__name__)
        return True, 0


def record_failure(ip: str, username: str) -> None:
    try:
        client = rate_limit._redis_client()
        pipe = client.pipeline()
        for scope, value in (("user", f"{ip}:{username}"), ("ip", ip)):
            key = _key(scope, value)
            pipe.incr(key)
            pipe.expire(key, WINDOW_SECONDS)
        pipe.execute()
    except Exception as exc:
        logger.error("Could not record login failure: %s", type(exc).__name__)


def record_success(ip: str, username: str) -> None:
    """Clear the per-user counter. The per-IP counter is left to expire."""
    try:
        rate_limit._redis_client().delete(_key("user", f"{ip}:{username}"))
    except Exception as exc:
        logger.error("Could not clear login failures: %s", type(exc).__name__)
