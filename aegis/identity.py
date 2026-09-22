"""
Workload identity: authenticate a caller by the token its platform already
issued it, instead of by a long-lived Aegis API key.

A Kubernetes pod, a GitHub Actions job and anything else with an OIDC issuer
can already prove what it is. An API key, by contrast, is a bearer secret that
has to be created, delivered, stored, rotated and eventually leaked. Removing
it for workloads that have a verifiable identity is the single biggest
reduction in credential handling available here.

This does not change the authorisation model. A verified identity resolves to
the same team and registry an API key would have, and everything after that -
policy resolution, rate limiting, auditing, caching - is the existing path.
What changes is only how the caller proves who it is.

    projected ServiceAccount token
        |  iss = https://kubernetes.default.svc.cluster.local
        |  sub = system:serviceaccount:payments:api
        |  aud = aegis
        v
    identity_bindings row (issuer + audience + subject [+ claim rules])
        v
    team + registry
        v
    policy, fetch, audit

Verification rules, and why each one is here:

  * Only asymmetric signatures (RS*, PS*, ES*, EdDSA). `alg: none` and the
    HMAC family are rejected outright: a verifier that accepts HS256 against
    a key fetched from a JWKS lets anyone who can read that public key sign
    their own tokens with it.
  * The issuer must match a configured binding. There is no discovery of
    arbitrary issuers.
  * The audience must match the binding. A ServiceAccount token minted for
    another service must not be replayable against Aegis, which is why the
    binding requires an explicit audience rather than defaulting to "any".
  * exp/nbf/iat are enforced with a small, fixed skew allowance.
  * JWKS documents are fetched through url_guard, so an issuer URL cannot be
    turned into an SSRF primitive even though only an admin can set one.

Not solved here: replay of a still-valid token by someone who obtained it.
These tokens are short-lived and audience-bound, which is the usual mitigation;
a nonce store would be the next step if that is not enough.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKSet

from aegis import url_guard

logger = logging.getLogger("aegis.identity")

# Asymmetric only. See the module docstring for why the HMAC family is absent.
ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512",
                      "PS256", "PS384", "PS512",
                      "ES256", "ES384", "ES512",
                      "EdDSA")

LEEWAY_SECONDS = 60          # clock skew tolerance
JWKS_TTL_SECONDS = int(os.environ.get("IDENTITY_JWKS_TTL_SECONDS", "300"))
JWKS_TIMEOUT_SECONDS = 5
MAX_TOKEN_BYTES = 8192       # a JWT far beyond this is not a credential


class IdentityError(Exception):
    """Token rejected. The message is safe to log, never to return verbatim."""


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str
    audience: str
    claims: dict[str, Any]

    @property
    def label(self) -> str:
        """Short, non-sensitive description for audit rows."""
        return f"{self.subject}@{self.issuer}"


# --------------------------------------------------------------------------
# JWKS retrieval
# --------------------------------------------------------------------------

_jwks_cache: dict[str, tuple[float, PyJWKSet]] = {}
_jwks_lock = threading.Lock()


def _discover_jwks_uri(issuer: str) -> str:
    """
    Resolve the issuer's JWKS URI via OIDC discovery.

    Goes through url_guard: the issuer is admin-configured, but a secrets
    broker fetching an arbitrary admin-supplied URL is exactly the shape of
    the SSRF problem this codebase already defends against elsewhere.
    """
    well_known = issuer.rstrip("/") + "/.well-known/openid-configuration"
    reason = url_guard.check_url(well_known)
    if reason:
        raise IdentityError(f"issuer discovery blocked: {reason}")
    resp = url_guard.request("GET", well_known, timeout=JWKS_TIMEOUT_SECONDS)
    if not resp.ok:
        raise IdentityError(f"issuer discovery failed [{resp.status_code}]")
    uri = (resp.json() or {}).get("jwks_uri")
    if not uri:
        raise IdentityError("issuer discovery returned no jwks_uri")
    return uri


def _fetch_jwks(issuer: str) -> PyJWKSet:
    uri = _discover_jwks_uri(issuer)
    reason = url_guard.check_url(uri)
    if reason:
        raise IdentityError(f"jwks fetch blocked: {reason}")
    resp = url_guard.request("GET", uri, timeout=JWKS_TIMEOUT_SECONDS)
    if not resp.ok:
        raise IdentityError(f"jwks fetch failed [{resp.status_code}]")
    try:
        return PyJWKSet.from_dict(resp.json())
    except Exception as exc:
        raise IdentityError(f"jwks document invalid: {type(exc).__name__}") from exc


def get_jwks(issuer: str, *, force: bool = False) -> PyJWKSet:
    """
    Cached JWKS for an issuer.

    Cached for JWKS_TTL_SECONDS so a burst of requests does not become a
    burst of outbound fetches. `force` re-reads, which the verifier does once
    when a key id is unknown, so a rotated signing key is picked up without
    waiting for the TTL.
    """
    now = time.monotonic()
    if not force:
        with _jwks_lock:
            cached = _jwks_cache.get(issuer)
        if cached and now - cached[0] < JWKS_TTL_SECONDS:
            return cached[1]

    jwks = _fetch_jwks(issuer)
    with _jwks_lock:
        _jwks_cache[issuer] = (now, jwks)
    return jwks


def clear_jwks_cache() -> None:
    with _jwks_lock:
        _jwks_cache.clear()


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def looks_like_jwt(token: str) -> bool:
    """
    Cheap discriminator so one Authorization header can carry either kind of
    credential. API keys have a fixed prefix; a JWT is three base64url
    segments.
    """
    return token.count(".") == 2 and not token.startswith("sk_")


def unverified_issuer(token: str) -> str | None:
    """
    Issuer claimed by an unverified token, used only to select which bindings
    to verify against. Nothing is trusted until the signature checks out.
    """
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None
    iss = claims.get("iss")
    return iss if isinstance(iss, str) and iss else None


def _signing_key(token: str, issuer: str):
    header = jwt.get_unverified_header(token)
    alg = header.get("alg")
    if alg not in ALLOWED_ALGORITHMS:
        raise IdentityError(f"algorithm {alg!r} not permitted")
    kid = header.get("kid")

    for force in (False, True):
        jwks = get_jwks(issuer, force=force)
        for key in jwks.keys:
            if kid is None or key.key_id == kid:
                return key.key
        if force:
            break
    raise IdentityError(f"no signing key for kid {kid!r}")


def verify(token: str, *, issuer: str, audience: str) -> VerifiedIdentity:
    """
    Verify a token against one issuer and audience. Raises IdentityError.
    """
    if len(token.encode()) > MAX_TOKEN_BYTES:
        raise IdentityError("token too large")

    key = _signing_key(token, issuer)
    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=list(ALLOWED_ALGORITHMS),
            issuer=issuer,
            audience=audience,
            leeway=LEEWAY_SECONDS,
            options={
                "require": ["exp", "iat", "iss", "sub", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.PyJWTError as exc:
        raise IdentityError(f"token rejected: {type(exc).__name__}") from exc

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise IdentityError("token has no usable subject")

    return VerifiedIdentity(issuer=issuer, subject=subject, audience=audience, claims=claims)


def claims_match(claims: dict, rules: dict | None) -> bool:
    """
    Whether every rule is satisfied.

    A rule is an exact match on a top-level claim, or on one element when the
    claim is a list. Absent claim means no match: a rule that cannot be
    evaluated has not been satisfied.
    """
    if not rules:
        return True
    for name, expected in rules.items():
        actual = claims.get(name)
        if isinstance(actual, list):
            if expected not in actual:
                return False
        elif actual != expected:
            return False
    return True
