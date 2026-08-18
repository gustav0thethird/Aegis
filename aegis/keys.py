"""
keys.py — API key generation, hashing and preview formatting.

Shared by the request path and the rotation scheduler so a key minted by one is
indistinguishable from a key minted by the other. These previously existed as
separate copies in api.py and scheduler.py, which is how the inbound webhook
path ended up issuing keys in a different format.
"""

import hashlib
import secrets

KEY_PREFIX = "sk_"
_PREVIEW_CHARS = 10


def generate_key() -> str:
    """Mint a new API key."""
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    """The stored form. Plaintext keys are never persisted."""
    return hashlib.sha256(key.encode()).hexdigest()


def preview(key: str) -> str:
    """Short display form, used in the UI and audit records."""
    return key[:_PREVIEW_CHARS] + "..."
