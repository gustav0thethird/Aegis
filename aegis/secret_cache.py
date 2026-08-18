"""
secret_cache.py — Short-lived cache for brokered secret fetches.

The External Secrets Operator refreshes on a timer, so without a cache every
ExternalSecret tick becomes a round trip to Vault, CyberArk, Conjur or AWS.
Across a cluster with many workloads that is sustained load on the upstream
vault for values that have not changed.

Two deliberate choices, both because this holds plaintext credentials:

  In-process, not Redis. A shared cache of plaintext secrets would widen the
  blast radius of a Redis compromise from "sessions and rate counters" to
  "every secret Aegis has brokered recently". Process memory dies with the
  process and is not reachable from another service.

  Off by default. Holding a credential in memory for longer than the request
  that needed it is a trade-off an operator should opt into knowingly, not
  inherit from a default. Set a TTL when vault load justifies it.

Entries are keyed by the hashed API key, so two teams never share a cache
entry even for the same underlying object.

Config:
  SECRET_CACHE_TTL_SECONDS — how long to retain a fetch (default 0 = disabled)
  SECRET_CACHE_MAX_ENTRIES — bound on entries before eviction (default 512)
"""

import os
import threading
import time
from collections import OrderedDict

_lock = threading.Lock()
_entries: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()


def ttl_seconds() -> int:
    try:
        return max(0, int(os.environ.get("SECRET_CACHE_TTL_SECONDS", "0")))
    except ValueError:
        return 0


def max_entries() -> int:
    try:
        return max(1, int(os.environ.get("SECRET_CACHE_MAX_ENTRIES", "512")))
    except ValueError:
        return 512


def enabled() -> bool:
    return ttl_seconds() > 0


def make_key(key_hash: str, scope: str) -> str:
    """
    Cache key for one API key's view of one scope.

    key_hash is already the stored hash of the API key, never the key itself.
    scope is an object name, or "*" for a whole registry.
    """
    return f"{key_hash}:{scope}"


def get(key: str) -> dict | None:
    """Return the cached mapping, or None if absent or expired."""
    if not enabled():
        return None
    now = time.monotonic()
    with _lock:
        entry = _entries.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at <= now:
            _entries.pop(key, None)
            return None
        _entries.move_to_end(key)
        return dict(value)


def put(key: str, value: dict) -> None:
    if not enabled():
        return
    expires_at = time.monotonic() + ttl_seconds()
    limit = max_entries()
    with _lock:
        _entries[key] = (expires_at, dict(value))
        _entries.move_to_end(key)
        while len(_entries) > limit:
            _entries.popitem(last=False)


def invalidate(key_hash: str) -> int:
    """
    Drop every entry belonging to one API key.

    Called when a key is revoked or rotated: a cached value must not outlive
    the credential that was allowed to fetch it.
    """
    prefix = f"{key_hash}:"
    with _lock:
        stale = [k for k in _entries if k.startswith(prefix)]
        for k in stale:
            del _entries[k]
    return len(stale)


def clear() -> None:
    with _lock:
        _entries.clear()


def stats() -> dict:
    with _lock:
        return {"entries": len(_entries), "ttl_seconds": ttl_seconds(),
                "enabled": enabled()}
