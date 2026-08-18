"""
Tests for DNS-pinned outbound requests.

Validating a hostname and then letting the HTTP client resolve it again leaves a
window: an attacker controlling DNS with a short TTL can answer with a public
address for the check and a private one for the connection.

url_guard.request() closes it by connecting to the address validation actually
saw. That only helps if TLS still verifies against the *name* — otherwise the
fix would trade an SSRF window for a downgrade to unauthenticated transport.
These tests run a real HTTPS server to prove it does.
"""

import datetime
import http.server
import socket
import ssl
import threading

import pytest

from aegis import url_guard

HOSTNAME = "pinned.test"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("WEBHOOK_ALLOWED_SCHEMES", "WEBHOOK_ALLOWED_HOSTS",
                "WEBHOOK_ALLOW_PRIVATE_IPS", "WEBHOOK_PIN_DNS"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    """A self-signed certificate whose SAN is HOSTNAME, not the address."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), critical=False)
        .sign(key, hashes.SHA256())
    )

    d = tmp_path_factory.mktemp("tls")
    cert_path, key_path = d / "cert.pem", d / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return str(cert_path), str(key_path)


class _Handler(http.server.BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        type(self).received.append({
            "host": self.headers.get("Host"),
            "path": self.path,
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):
        pass


@pytest.fixture
def tls_server(tls_material):
    """Serve HTTPS on 127.0.0.1 with a certificate issued for HOSTNAME."""
    cert_path, key_path = tls_material
    _Handler.received = []

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], cert_path
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def resolves_to_loopback(monkeypatch):
    """Make HOSTNAME resolve to 127.0.0.1, as a rebind would."""
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        if host == HOSTNAME:
            return real("127.0.0.1", port, *args, **kwargs)
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(url_guard.socket, "getaddrinfo", fake)


class TestPinnedRequestOverTls:

    def test_reaches_the_pinned_address_and_verifies_the_certificate(
            self, tls_server, resolves_to_loopback, monkeypatch):
        """
        The connection goes to the validated IP, yet TLS is still checked
        against the hostname — a certificate issued only for HOSTNAME is
        accepted while connecting to a literal address.
        """
        port, ca = tls_server
        monkeypatch.setenv("WEBHOOK_ALLOW_PRIVATE_IPS", "true")

        resp = url_guard.request(
            "POST", f"https://{HOSTNAME}:{port}/hook",
            json={"event": "test"}, verify=ca, timeout=10,
        )

        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    def test_host_header_keeps_the_original_name(
            self, tls_server, resolves_to_loopback, monkeypatch):
        """Virtual-hosted endpoints must still route correctly."""
        port, ca = tls_server
        monkeypatch.setenv("WEBHOOK_ALLOW_PRIVATE_IPS", "true")

        url_guard.request("POST", f"https://{HOSTNAME}:{port}/hook",
                          json={}, verify=ca, timeout=10)

        assert _Handler.received[0]["host"] == f"{HOSTNAME}:{port}"

    def test_path_and_query_survive_rewriting(
            self, tls_server, resolves_to_loopback, monkeypatch):
        port, ca = tls_server
        monkeypatch.setenv("WEBHOOK_ALLOW_PRIVATE_IPS", "true")

        url_guard.request("POST", f"https://{HOSTNAME}:{port}/a/b?x=1",
                          json={}, verify=ca, timeout=10)

        assert _Handler.received[0]["path"] == "/a/b?x=1"


class TestPinnedRequestValidation:

    def test_rejected_url_never_reaches_the_network(self, monkeypatch):
        called = []
        monkeypatch.setattr(url_guard.requests, "request",
                            lambda *a, **k: called.append(1))

        with pytest.raises(ValueError, match="scheme"):
            url_guard.request("POST", "http://hooks.example.com/x")

        assert called == []

    def test_private_target_is_rejected_by_default(self):
        with pytest.raises(ValueError):
            url_guard.request("POST", "https://127.0.0.1/x", timeout=1)


class TestPinUrl:

    def test_rewrites_host_only(self):
        assert url_guard.pin_url("https://hooks.example.com/a/b?x=1", "93.184.216.34") \
            == "https://93.184.216.34/a/b?x=1"

    def test_preserves_an_explicit_port(self):
        assert url_guard.pin_url("https://hooks.example.com:8443/a", "93.184.216.34") \
            == "https://93.184.216.34:8443/a"

    def test_brackets_ipv6(self):
        assert url_guard.pin_url("https://hooks.example.com/a", "2606:2800::1") \
            == "https://[2606:2800::1]/a"


class TestPinningToggle:

    def test_enabled_by_default(self):
        assert url_guard.pinning_enabled() is True

    def test_can_be_disabled(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_PIN_DNS", "false")
        assert url_guard.pinning_enabled() is False

    def test_literal_ip_skips_pinning(self, monkeypatch):
        """A literal address is already unambiguous; no rewrite is needed."""
        seen = {}
        monkeypatch.setenv("WEBHOOK_ALLOW_PRIVATE_IPS", "true")
        monkeypatch.setattr(url_guard.requests, "request",
                            lambda method, url, **k: seen.setdefault("url", url))

        url_guard.request("POST", "https://10.0.0.5/x")

        assert seen["url"] == "https://10.0.0.5/x"
