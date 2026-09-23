"""
Security response headers.

The broker served its admin UI with none: no Content-Security-Policy, so an
injected script ran unhindered; no X-Frame-Options or frame-ancestors, so the
console could be framed and clickjacked into rotating a key or deleting a
team; no nosniff, so a stored value served from an API route could be
rendered as HTML; and a full Referer on every outbound link, which leaks
team and registry identifiers in paths.

The policy below is only meaningful because the pages carry no inline script.
Handlers name entries in an ACTIONS map (static/js/actions.js) and page
scripts are served from /static, so script-src can be 'self' alone, with no
'unsafe-inline' and no 'unsafe-eval'. That is the directive that actually
stops XSS; the rest is depth.

Inline *style attributes* are a different matter. The templates carry several
hundred, so they are allowed -- but only as attributes, and only where the
browser understands the distinction:

    style-src       'self' 'unsafe-inline' <fonts>   fallback for CSP2
    style-src-elem  'self' <fonts>                   no inline <style> blocks
    style-src-attr  'unsafe-inline'                  style="..." only

A CSP3 browser applies the two specific directives and ignores style-src, so
an injected <style> element is refused. A CSP2 browser falls back to
style-src, which keeps the UI rendering rather than stripping it.
"""
import os

from starlette.types import ASGIApp, Message, Receive, Scope, Send

FONT_CSS = "https://fonts.googleapis.com"
FONT_FILES = "https://fonts.gstatic.com"

CSP = "; ".join([
    "default-src 'self'",
    # No inline script and no eval: the whole point of the policy.
    "script-src 'self'",
    # Explicit even though script-src covers it: an event-handler attribute
    # is refused outright, so one reintroduced by accident fails loudly.
    "script-src-attr 'none'",
    f"style-src 'self' 'unsafe-inline' {FONT_CSS}",
    f"style-src-elem 'self' {FONT_CSS}",
    "style-src-attr 'unsafe-inline'",
    f"font-src 'self' {FONT_FILES}",
    # data: for the inline SVG icons the UI draws.
    "img-src 'self' data:",
    "connect-src 'self'",
    # The UI never frames anything and must never be framed.
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
])

PERMISSIONS_POLICY = ", ".join(
    f"{feature}=()" for feature in
    ("accelerometer", "camera", "geolocation", "gyroscope", "magnetometer",
     "microphone", "payment", "usb", "interest-cohort")
)

STATIC_HEADERS = {
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    # frame-ancestors supersedes this; kept for anything that predates CSP3.
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": PERMISSIONS_POLICY,
}


def _hsts_value():
    """
    None disables HSTS. It is worth getting wrong in only one direction: a
    max-age served by mistake pins every browser that saw it to HTTPS for
    that long, and cannot be withdrawn from those browsers quickly.
    """
    max_age = os.environ.get("HSTS_MAX_AGE", "31536000").strip()
    if max_age in ("", "0", "off", "false"):
        return None
    value = f"max-age={int(max_age)}"
    if os.environ.get("HSTS_INCLUDE_SUBDOMAINS", "true").lower() in ("1", "true", "yes"):
        value += "; includeSubDomains"
    if os.environ.get("HSTS_PRELOAD", "false").lower() in ("1", "true", "yes"):
        value += "; preload"
    return value


def _is_https(scope: Scope) -> bool:
    if scope.get("scheme") == "https":
        return True
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-proto":
            return value.decode("latin-1").split(",")[0].strip().lower() == "https"
    return False


class SecurityHeadersMiddleware:
    """
    Adds the headers above to every response.

    Written against the ASGI interface rather than BaseHTTPMiddleware so it
    does not buffer streaming responses -- the audit and changelog exports
    stream CSV.
    """

    def __init__(self, app: ASGIApp):
        self.app = app
        self.hsts = _hsts_value()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                present = {name.lower() for name, _ in headers}
                for name, value in STATIC_HEADERS.items():
                    # A route that sets its own policy keeps it.
                    if name.encode() not in present:
                        headers.append((name.encode(), value.encode()))
                if self.hsts and _is_https(scope) and b"strict-transport-security" not in present:
                    headers.append((b"strict-transport-security", self.hsts.encode()))
            await send(message)

        await self.app(scope, receive, send_with_headers)
