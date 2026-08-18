"""
Unit tests for the outbound URL guard (SSRF protection).

DNS is stubbed throughout, so these are deterministic and need no network.
"""

import socket

import pytest

from aegis import url_guard

PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("WEBHOOK_ALLOWED_SCHEMES", "WEBHOOK_ALLOWED_HOSTS", "WEBHOOK_ALLOW_PRIVATE_IPS"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def resolves_to(monkeypatch):
    """Make every hostname lookup return the given address."""
    def _apply(address):
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                     (address, port or 443))]
        monkeypatch.setattr(url_guard.socket, "getaddrinfo", fake_getaddrinfo)
    return _apply


class TestScheme:
    def test_https_is_allowed(self, resolves_to):
        resolves_to(PUBLIC_IP)
        assert url_guard.is_safe("https://hooks.example.com/abc")

    def test_http_is_rejected_by_default(self, resolves_to):
        resolves_to(PUBLIC_IP)
        assert "scheme" in url_guard.check_url("http://hooks.example.com/abc")

    def test_file_scheme_is_rejected(self):
        assert "scheme" in url_guard.check_url("file:///etc/passwd")

    def test_scheme_list_is_configurable(self, monkeypatch, resolves_to):
        monkeypatch.setenv("WEBHOOK_ALLOWED_SCHEMES", "http,https")
        resolves_to(PUBLIC_IP)
        assert url_guard.is_safe("http://hooks.example.com/abc")


class TestPrivateAddresses:
    @pytest.mark.parametrize("address", [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.10",
        "172.16.0.9",
        "169.254.169.254",   # cloud instance metadata service
        "0.0.0.0",
    ])
    def test_non_public_resolution_is_rejected(self, resolves_to, address):
        resolves_to(address)
        assert url_guard.check_url("https://internal.example.com/hook") is not None

    def test_literal_metadata_ip_is_rejected_without_dns(self):
        assert url_guard.check_url("https://169.254.169.254/latest/meta-data") is not None

    def test_ipv6_loopback_is_rejected(self):
        assert url_guard.check_url("https://[::1]/hook") is not None

    def test_ipv4_mapped_loopback_is_rejected(self):
        assert url_guard.check_url("https://[::ffff:127.0.0.1]/hook") is not None

    def test_public_address_is_allowed(self, resolves_to):
        resolves_to(PUBLIC_IP)
        assert url_guard.is_safe("https://hooks.example.com/hook")

    def test_escape_hatch_permits_private_targets(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_ALLOW_PRIVATE_IPS", "true")
        assert url_guard.is_safe("https://127.0.0.1:9000/hook")


class TestHostAllowlist:
    def test_listed_host_is_allowed(self, monkeypatch, resolves_to):
        monkeypatch.setenv("WEBHOOK_ALLOWED_HOSTS", "hooks.example.com")
        resolves_to(PUBLIC_IP)
        assert url_guard.is_safe("https://hooks.example.com/x")

    def test_subdomain_of_listed_parent_is_allowed(self, monkeypatch, resolves_to):
        monkeypatch.setenv("WEBHOOK_ALLOWED_HOSTS", "example.com")
        resolves_to(PUBLIC_IP)
        assert url_guard.is_safe("https://hooks.example.com/x")

    def test_unlisted_host_is_rejected(self, monkeypatch, resolves_to):
        monkeypatch.setenv("WEBHOOK_ALLOWED_HOSTS", "example.com")
        resolves_to(PUBLIC_IP)
        assert "WEBHOOK_ALLOWED_HOSTS" in url_guard.check_url("https://evil.test/x")

    def test_suffix_confusion_is_rejected(self, monkeypatch, resolves_to):
        """notexample.com must not satisfy an example.com allowlist entry."""
        monkeypatch.setenv("WEBHOOK_ALLOWED_HOSTS", "example.com")
        resolves_to(PUBLIC_IP)
        assert url_guard.check_url("https://notexample.com/x") is not None


class TestMalformed:
    def test_empty_url_is_rejected(self):
        assert url_guard.check_url("") is not None

    def test_url_without_host_is_rejected(self):
        assert url_guard.check_url("https:///nohost") is not None

    def test_embedded_credentials_are_rejected(self, resolves_to):
        resolves_to(PUBLIC_IP)
        assert "credentials" in url_guard.check_url("https://user:pw@hooks.example.com/x")

    def test_unresolvable_host_is_rejected(self, monkeypatch):
        def boom(*args, **kwargs):
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(url_guard.socket, "getaddrinfo", boom)
        assert "resolved" in url_guard.check_url("https://nope.invalid/x")


class TestValidateUrl:
    def test_returns_trimmed_url_when_safe(self, resolves_to):
        resolves_to(PUBLIC_IP)
        assert url_guard.validate_url("  https://hooks.example.com/x  ") == \
            "https://hooks.example.com/x"

    def test_error_names_the_offending_field(self, resolves_to):
        resolves_to("127.0.0.1")
        with pytest.raises(ValueError, match="slack_webhook_url"):
            url_guard.validate_url("https://internal.example.com/x", "slack_webhook_url")
