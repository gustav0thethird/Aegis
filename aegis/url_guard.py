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
                              targets. Local development only; never set this
                              in production.
  WEBHOOK_PIN_DNS           — "false" disables connection pinning (default on).

DNS rebinding: a hostname validated here could be re-pointed at a private
address before the request is made. request() closes that window by connecting
to the address validation actually resolved, while TLS and the Host header keep
using the hostname. Set WEBHOOK_PIN_DNS=false to fall back to ordinary
resolution.
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


def check_url(url: str, allow_private: bool = False) -> str | None:
    """
    Return None if the URL is safe to request, otherwise a reason string.

    allow_private relaxes only the address checks, for destinations configured
    by the operator rather than supplied by a user — a self-hosted Jira or
    ServiceNow on RFC1918 space is a normal deployment, not an SSRF attempt.
    Scheme and embedded-credential checks still apply.
    """
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

    if allow_private or _allow_private():
        return None

    addresses, reason = _resolve(hostname, parsed.port or 443)
    return reason


def _resolve(hostname: str, port: int, allow_private: bool = False) -> tuple[list[str], str | None]:
    """
    Resolve a hostname and check every address it maps to.

    Returns (addresses, None) when acceptable, or ([], reason) otherwise. A
    literal IP needs no lookup and is checked directly. allow_private skips the
    address check but still returns the resolved addresses, so a caller can pin
    the connection even where private targets are permitted.
    """
    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            return [], f"host '{hostname}' could not be resolved: {exc}"
        addresses = [info[4][0] for info in infos]

    if not addresses:
        return [], f"host '{hostname}' did not resolve to any address"

    if not allow_private:
        for addr in addresses:
            if _is_blocked_ip(addr):
                return [], f"host '{hostname}' resolves to non-public address {addr}"

    return addresses, None


def validate_url(url: str, field: str = "url", allow_private: bool = False) -> str:
    """Return the trimmed URL, or raise ValueError describing why it was rejected."""
    reason = check_url(url, allow_private=allow_private)
    if reason:
        raise ValueError(f"{field}: {reason}")
    return url.strip()


def is_safe(url: str, allow_private: bool = False) -> bool:
    return check_url(url, allow_private=allow_private) is None


# ---------------------------------------------------------------------------
# Pinned requests — closing the DNS rebinding window
# ---------------------------------------------------------------------------
#
# Validating a hostname and then letting the HTTP client resolve it again leaves
# a gap: an attacker controlling DNS with a short TTL can answer with a public
# address for the check and a private one for the connection. Re-checking at
# delivery narrows that gap to milliseconds but does not close it.
#
# request() closes it by connecting to the address that was actually validated.
# The URL is rewritten to that address while the Host header and TLS SNI keep
# the original hostname, so virtual hosting and certificate verification behave
# exactly as they would have.

import requests                                   # noqa: E402
from requests.adapters import HTTPAdapter         # noqa: E402


class _PinnedAdapter(HTTPAdapter):
    """Route to a fixed address while presenting the original hostname to TLS."""

    def __init__(self, hostname: str, **kwargs):
        self._hostname = hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        # server_hostname drives SNI; assert_hostname keeps certificate
        # verification bound to the name rather than the literal address.
        kwargs["server_hostname"] = self._hostname
        kwargs["assert_hostname"] = self._hostname
        super().init_poolmanager(*args, **kwargs)


def pin_url(url: str, address: str) -> str:
    """Rewrite `url` so the connection targets `address`, preserving path and port."""
    parsed = urlparse(url)
    host = f"[{address}]" if ":" in address else address
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return parsed._replace(netloc=netloc).geturl()


def pinning_enabled() -> bool:
    return os.environ.get("WEBHOOK_PIN_DNS", "true").strip().lower() != "false"


def request(method: str, url: str, *, allow_private: bool = False, **kwargs):
    """
    Make an outbound request only if the URL validates, connecting to the
    address that validation actually saw.

    Raises ValueError if the URL must not be requested at all.
    """
    reason = check_url(url, allow_private=allow_private)
    if reason:
        raise ValueError(reason)

    parsed = urlparse(url.strip())
    hostname = (parsed.hostname or "").lower()

    # Pinning only means anything for a name that had to be resolved. A literal
    # IP is already unambiguous, and when private targets are permitted there is
    # nothing the rebind could escalate to.
    is_literal_ip = True
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_literal_ip = False

    if not pinning_enabled() or is_literal_ip:
        return requests.request(method, url, **kwargs)

    addresses, reason = _resolve(hostname, parsed.port or 443,
                                 allow_private=allow_private or _allow_private())
    if reason:
        raise ValueError(reason)

    headers = dict(kwargs.pop("headers", None) or {})
    headers.setdefault("Host", parsed.netloc)

    with requests.Session() as session:
        session.mount("https://", _PinnedAdapter(hostname))
        session.mount("http://", HTTPAdapter())
        return session.request(method, pin_url(url, addresses[0]),
                               headers=headers, **kwargs)
