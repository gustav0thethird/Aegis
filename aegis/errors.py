"""
Error and payload sanitisation.

Aegis sits in front of secrets, so the default has to be that nothing derived
from an upstream response or a credential-bearing event reaches a caller, an
audit row, a webhook delivery record, a log line or a SIEM sink.

Two rules, both enforced here rather than left to each call site:

  * Upstream failures raise UpstreamError, which carries the vendor, the
    operation and the status code - never the response body. For CyberArk and
    Conjur the body of a successful GET *is* the secret, so the body is not
    safe to put in an exception even on a failure path: the same field carries
    the password when the call succeeds.

  * Event payloads are redacted before they are persisted. The plaintext key in
    a key.rotated event has to reach the subscriber over HTTPS, but it must not
    survive in webhook_log.
"""
from __future__ import annotations

# Payload keys whose values never get written down, whatever the event.
SENSITIVE_KEYS = frozenset({
    "new_key", "api_key", "key", "password", "secret", "token",
    "client_secret", "private_key", "credential", "credentials",
})

REDACTED = "[redacted]"

# What a caller is told when an upstream provider fails. Operators correlate
# the audit row and the server log by timestamp for the vendor and status code.
PUBLIC_UPSTREAM_MESSAGE = "Secret provider request failed"


class UpstreamError(Exception):
    """
    A vendor call failed. Carries only non-sensitive identifiers.

    `audit_detail` is what may be written to the audit log and shipped to a
    SIEM; `public_message` is what an API caller sees.
    """

    def __init__(self, vendor: str, operation: str, status_code: int | None = None,
                 reason: str | None = None):
        self.vendor = vendor
        self.operation = operation
        self.status_code = status_code
        # `reason` is for text the caller has constructed itself, never text
        # taken from a response body.
        self.reason = reason
        super().__init__(self.audit_detail)

    @property
    def audit_detail(self) -> str:
        parts = [f"{self.vendor} {self.operation} failed"]
        if self.status_code is not None:
            parts.append(f"[{self.status_code}]")
        if self.reason:
            parts.append(f": {self.reason}")
        return " ".join(parts[:2]) + (parts[2] if len(parts) > 2 else "")

    @property
    def public_message(self) -> str:
        return PUBLIC_UPSTREAM_MESSAGE


def redact(payload: dict) -> dict:
    """
    Copy of `payload` with sensitive values replaced. Nested dicts and lists of
    dicts are walked, so a key buried in a sub-object is caught too.

    Keys are redacted when present and truthy, so a `new_key: None` on an event
    that is not a rotation stays None rather than becoming a misleading marker.
    """
    out: dict = {}
    for k, v in payload.items():
        if k in SENSITIVE_KEYS and v:
            out[k] = REDACTED
        elif isinstance(v, dict):
            out[k] = redact(v)
        elif isinstance(v, list):
            out[k] = [redact(i) if isinstance(i, dict) else i for i in v]
        else:
            out[k] = v
    return out


def safe_detail(exc: BaseException) -> str:
    """
    Text that is safe to persist for an exception.

    An UpstreamError has already been constructed without a response body. For
    anything else only the type name is recorded: an arbitrary exception's
    string form may embed whatever the caller passed to it.
    """
    if isinstance(exc, UpstreamError):
        return exc.audit_detail
    return type(exc).__name__
