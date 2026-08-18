"""
url_guard.py — Validation for user-supplied outbound URLs.

Team webhook and notification URLs are POSTed to by the broker itself, so an
unvalidated URL turns Aegis into an SSRF pivot into its own network. The
key.rotated payload carries a plaintext key, so an attacker-controlled URL is
an exfiltration channel as well as a probe.

Every URL that the server will later request must pass validate_url() at the
point it is accepted, and again at delivery time for rows written before this
check existed.

Config:
  WEBHOOK_ALLOWED_SCHEMES   — comma-separated (default: https)
  WEBHOOK_ALLOWED_HOSTS     — comma-separated allowlist. Empty means "any
                              public host". An entry matches the host exactly,
                              or as a parent domain (example.com matches
                              hooks.example.com).
  WEBHOOK_ALLOW_PRIVATE_IPS — "true" permits loopback/RFC1918/link-local
                              targets and skips DNS resolution. Local
                              development only; never set this in production.

Note on TOCTOU: a hostname validated here can be re-pointed at a private
address before the request is made (DNS rebinding). Re-validating at delivery
time narrows that window but does not close it. Closing it entirely requires
pinning the resolved address for the connection, which is why the host
allowlist exists for deployments that need a hard guarantee.
"""

import ipaddress
import os
import socket
from urllib.parse import urlparse

_DEFAULT_SCHEMES = "https"


def _env_list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _allow_private() -> bool:
    return os.environ.get("WEBHOOK_ALLOW_PRIVATE_IPS", "").strip().lower() in {"1", "true", "yes"}


def _host_allowed(hostname: str, allowlist: list[str]) -> bool:
    if not allowlist:
        return True
    return any(hostname == entry or hostname.endswith("." + entry) for entry in allowlist)


def _is_blocked_ip(addr: str) -> bool:
    """True if addr is in a range that must never be reachable from a webhook."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable — treat as unsafe

    # ::ffff:127.0.0.1 and friends are loopback wearing an IPv6 hat.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def check_url(url: str) -> str | None:
    """Return None if the URL is safe to request, otherwise a reason string."""
    if not url or not url.strip():
        return "URL is empty"

    try:
        parsed = urlparse(url.strip())
    except Exception as exc:
        return f"URL could not be parsed: {exc}"

    schemes = _env_list("WEBHOOK_ALLOWED_SCHEMES", _DEFAULT_SCHEMES)
    if parsed.scheme.lower() not in schemes:
        return f"URL scheme must be one of {sorted(schemes)}, got '{parsed.scheme or 'none'}'"

    if parsed.username or parsed.password:
        return "URL must not embed credentials"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return "URL has no host"

    allowlist = _env_list("WEBHOOK_ALLOWED_HOSTS")
    if not _host_allowed(hostname, allowlist):
        return f"host '{hostname}' is not in WEBHOOK_ALLOWED_HOSTS"

    if _allow_private():
        return None

    # A literal IP needs no lookup; a name has to be resolved, and *every*
    # address it resolves to must be public.
    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            return f"host '{hostname}' could not be resolved: {exc}"
        addresses = [info[4][0] for info in infos]

    if not addresses:
        return f"host '{hostname}' did not resolve to any address"

    for addr in addresses:
        if _is_blocked_ip(addr):
            return f"host '{hostname}' resolves to non-public address {addr}"

    return None


def validate_url(url: str, field: str = "url") -> str:
    """Return the trimmed URL, or raise ValueError describing why it was rejected."""
    reason = check_url(url)
    if reason:
        raise ValueError(f"{field}: {reason}")
    return url.strip()


def is_safe(url: str) -> bool:
    return check_url(url) is None
