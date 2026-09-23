"""
Security response headers.

The broker served its admin UI with none of these. The one that matters is
Content-Security-Policy: with no inline script anywhere in the pages,
script-src can be 'self' alone, so an injected handler or <script> is refused
by the browser rather than merely unlikely to be reachable.

The rest close smaller gaps: the console could be framed and clickjacked into
rotating a key, a stored value served from an API route could be sniffed as
HTML, and a full Referer leaked team and registry ids out of the deployment.

Requires PostgreSQL (aegis_test).
"""
import importlib

import pytest

from aegis import security_headers
from aegis.security_headers import CSP, SecurityHeadersMiddleware, _hsts_value, _is_https


def _directive(name, policy=CSP):
    for part in policy.split(";"):
        part = part.strip()
        if part.split(" ")[0] == name:
            return part
    return None


class TestTheScriptPolicyIsTheStrictPart:

    def test_script_src_allows_only_same_origin(self):
        assert _directive("script-src") == "script-src 'self'"

    @pytest.mark.parametrize("forbidden", ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"])
    def test_script_src_has_no_escape_hatch(self, forbidden):
        """Any of these would make the policy decorative."""
        assert forbidden not in _directive("script-src")

    def test_handler_attributes_are_refused_outright(self):
        assert _directive("script-src-attr") == "script-src-attr 'none'"

    def test_the_page_cannot_be_framed(self):
        assert _directive("frame-ancestors") == "frame-ancestors 'none'"

    @pytest.mark.parametrize("directive,expected", [
        ("default-src", "default-src 'self'"),
        ("object-src", "object-src 'none'"),
        ("base-uri", "base-uri 'none'"),
        ("form-action", "form-action 'self'"),
        ("connect-src", "connect-src 'self'"),
    ])
    def test_the_remaining_directives(self, directive, expected):
        assert _directive(directive) == expected


class TestInlineStylesAreAllowedOnlyAsAttributes:
    """
    The templates carry several hundred style attributes, so those stay. An
    injected <style> element is a different thing and is refused.
    """

    def test_style_elements_may_not_be_inline(self):
        assert "'unsafe-inline'" not in _directive("style-src-elem")

    def test_style_attributes_may_be_inline(self):
        assert _directive("style-src-attr") == "style-src-attr 'unsafe-inline'"

    def test_there_is_a_fallback_for_browsers_without_the_split(self):
        """
        A CSP2 browser ignores style-src-elem/attr entirely. Without
        'unsafe-inline' here it would strip the UI's styling instead.
        """
        assert "'unsafe-inline'" in _directive("style-src")


class TestHeadersReachEveryKindOfResponse:

    @pytest.mark.parametrize("path", ["/login", "/admin", "/dashboard", "/docs"])
    def test_ui_pages(self, client, path):
        assert client.get(path).headers["content-security-policy"] == CSP

    def test_static_assets(self, client):
        resp = client.get("/static/js/actions.js")
        assert resp.status_code == 200
        assert resp.headers["content-security-policy"] == CSP

    def test_api_responses(self, client):
        assert client.get("/health").headers["content-security-policy"] == CSP

    def test_error_responses(self, client):
        """Set by the outermost layer, so a handler-produced response is covered."""
        resp = client.get("/admin/api/objects")
        assert resp.status_code == 401
        assert resp.headers["content-security-policy"] == CSP

    def test_a_404_is_covered(self, client):
        resp = client.get("/no-such-path-exists")
        assert resp.status_code == 404
        assert "content-security-policy" in resp.headers

    @pytest.mark.parametrize("header,value", [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
    ])
    def test_the_other_headers(self, client, header, value):
        assert client.get("/login").headers[header] == value

    def test_permissions_policy_disables_device_access(self, client):
        policy = client.get("/login").headers["permissions-policy"]
        for feature in ("camera", "microphone", "geolocation", "payment", "usb"):
            assert f"{feature}=()" in policy


class TestStrictTransportSecurity:
    """
    An HSTS max-age served by mistake pins every browser that saw it, and
    cannot be withdrawn from those browsers quickly, so it goes out only on
    a connection that is actually HTTPS.
    """

    def test_not_sent_over_plain_http(self, client):
        assert "strict-transport-security" not in client.get("/login").headers

    def test_sent_when_a_proxy_reports_https(self, client):
        resp = client.get("/login", headers={"X-Forwarded-Proto": "https"})
        assert resp.headers["strict-transport-security"].startswith("max-age=")

    def test_a_proxy_reporting_http_does_not_get_it(self, client):
        assert "strict-transport-security" not in client.get(
            "/login", headers={"X-Forwarded-Proto": "http"}).headers

    def test_the_first_proto_in_a_chain_decides(self):
        scope = {"type": "http", "scheme": "http",
                 "headers": [(b"x-forwarded-proto", b"https, http")]}
        assert _is_https(scope) is True

    def test_a_direct_https_scope_counts(self):
        assert _is_https({"type": "http", "scheme": "https", "headers": []}) is True

    @pytest.mark.parametrize("value", ["0", "off", "false", ""])
    def test_it_can_be_turned_off(self, monkeypatch, value):
        monkeypatch.setenv("HSTS_MAX_AGE", value)
        assert _hsts_value() is None

    def test_max_age_and_subdomains_are_configurable(self, monkeypatch):
        monkeypatch.setenv("HSTS_MAX_AGE", "600")
        monkeypatch.setenv("HSTS_INCLUDE_SUBDOMAINS", "false")
        assert _hsts_value() == "max-age=600"

    def test_preload_is_opt_in(self, monkeypatch):
        monkeypatch.setenv("HSTS_MAX_AGE", "31536000")
        monkeypatch.setenv("HSTS_INCLUDE_SUBDOMAINS", "true")
        monkeypatch.setenv("HSTS_PRELOAD", "true")
        assert _hsts_value() == "max-age=31536000; includeSubDomains; preload"


class TestARouteMayKeepItsOwnPolicy:

    def test_an_existing_header_is_not_overwritten(self):
        """
        The middleware fills gaps rather than asserting control, so a route
        that needs its own policy can set one.
        """
        sent = {}

        class App:
            async def __call__(self, scope, receive, send):
                await send({"type": "http.response.start", "status": 200,
                            "headers": [(b"content-security-policy", b"default-src 'none'")]})
                await send({"type": "http.response.body", "body": b""})

        async def capture(message):
            if message["type"] == "http.response.start":
                sent["headers"] = message["headers"]

        async def receive():
            return {"type": "http.request"}

        import asyncio
        mw = SecurityHeadersMiddleware(App())
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            mw({"type": "http", "scheme": "http", "headers": []}, receive, capture))

        csps = [v for k, v in sent["headers"] if k == b"content-security-policy"]
        assert csps == [b"default-src 'none'"]

    def test_websocket_scopes_pass_through(self):
        """Only http responses carry headers; a non-http scope must not raise."""
        import asyncio
        seen = {}

        class App:
            async def __call__(self, scope, receive, send):
                seen["scope"] = scope["type"]

        mw = SecurityHeadersMiddleware(App())
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            mw({"type": "websocket"}, None, None))
        assert seen["scope"] == "websocket"


def test_the_module_reloads_cleanly(monkeypatch):
    """HSTS is read at construction, so a redeploy picks up a changed value."""
    monkeypatch.setenv("HSTS_MAX_AGE", "120")
    importlib.reload(security_headers)
    assert security_headers.SecurityHeadersMiddleware(lambda *a: None).hsts == "max-age=120; includeSubDomains"
    monkeypatch.delenv("HSTS_MAX_AGE")
    importlib.reload(security_headers)
