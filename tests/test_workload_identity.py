"""
Workload identity authentication.

A caller may present the OIDC token its platform already issued (a Kubernetes
projected ServiceAccount token, a GitHub Actions token) instead of a
long-lived Aegis API key. That replaces a stored bearer secret with a
short-lived, audience-bound assertion, which is the main reason to have it.

Most of this file is adversarial, because a token verifier is only as good as
the things it refuses: algorithm confusion, an unexpected audience, a
different issuer, an expired or not-yet-valid token, a tampered signature, an
unknown subject, unmet claim rules, a disabled binding.

Requires PostgreSQL (aegis_test). Tokens are signed here with a throwaway RSA
key; nothing contacts a real issuer, because get_jwks is stubbed.
"""
import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKSet
from jwt.utils import base64url_encode

from aegis import identity
from aegis.models import IdentityBinding, Object, Registry, RegistryObject, Team

ISSUER = "https://kubernetes.default.svc.cluster.local"
AUDIENCE = "aegis"
SUBJECT = "system:serviceaccount:payments:api"
KID = "test-key-1"


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_key():
    """A key the issuer does not publish, for forged-signature tests."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def stub_jwks(signing_key, monkeypatch):
    """
    Serve the public half as the issuer's JWKS. Nothing leaves the process:
    the discovery and fetch paths are exercised separately.
    """
    numbers = signing_key.public_key().public_numbers()

    def b64(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64url_encode(raw).decode()

    jwks = PyJWKSet.from_dict({"keys": [{
        "kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256",
        "n": b64(numbers.n), "e": b64(numbers.e),
    }]})
    monkeypatch.setattr(identity, "get_jwks", lambda issuer, force=False: jwks)
    identity.clear_jwks_cache()
    yield
    identity.clear_jwks_cache()


def make_token(signing_key, *, issuer=ISSUER, audience=AUDIENCE, subject=SUBJECT,
               kid=KID, algorithm="RS256", extra=None, exp_delta=300, iat_delta=0,
               nbf_delta=None):
    now = int(time.time())
    claims = {"iss": issuer, "sub": subject, "aud": audience,
              "iat": now + iat_delta, "exp": now + exp_delta}
    if nbf_delta is not None:
        claims["nbf"] = now + nbf_delta
    claims.update(extra or {})
    headers = {"kid": kid} if kid else {}
    return jwt.encode(claims, signing_key, algorithm=algorithm, headers=headers)


@pytest.fixture
def binding(db, _schema, client):
    obj = Object(name=_unique("obj"), vendor="vault", auth_ref="prod",
                 path="secret/test", created_by="test")
    reg = Registry(name=_unique("reg"), created_by="test")
    db.add(obj)
    db.add(reg)
    db.flush()
    db.add(RegistryObject(registry_id=reg.id, object_name=obj.name))
    team = Team(name=_unique("team"), created_by="test")
    db.add(team)
    db.commit()

    row = IdentityBinding(name=_unique("binding"), issuer=ISSUER, audience=AUDIENCE,
                          subject=SUBJECT, team_id=team.id, registry_id=reg.id,
                          enabled=True, created_by="test")
    db.add(row)
    db.commit()
    db.refresh(row)
    yield row, obj, reg, team
    db.query(IdentityBinding).filter(IdentityBinding.team_id == team.id).delete()
    db.commit()


def _headers(token):
    return {"Authorization": f"Bearer {token}", "X-Change-Number": "CHG-ID-1"}


class TestAcceptedIdentity:

    def test_valid_token_fetches_secrets(self, client, db, binding, signing_key, monkeypatch):
        _row, obj, _reg, _team = binding
        monkeypatch.setattr("aegis.deps.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "value-from-vault"})
        resp = client.get("/secrets", headers=_headers(make_token(signing_key)))
        assert resp.status_code == 200, resp.text
        assert resp.json() == {obj.name: "value-from-vault"}

    def test_use_is_recorded_on_the_binding(self, client, db, binding, signing_key, monkeypatch):
        row, _obj, _reg, _team = binding
        assert row.last_used_at is None
        monkeypatch.setattr("aegis.deps.fetch_secrets", lambda rows, auth: {"x": "v"})
        client.get("/secrets", headers=_headers(make_token(signing_key)))
        db.refresh(row)
        assert row.last_used_at is not None

    def test_audit_names_the_workload_not_a_key(self, client, db, binding, signing_key, monkeypatch):
        from aegis.models import AuditLog
        _row, _obj, reg, _team = binding
        monkeypatch.setattr("aegis.deps.fetch_secrets", lambda rows, auth: {"x": "v"})
        client.get("/secrets", headers=_headers(make_token(signing_key)))
        entry = (db.query(AuditLog)
                   .filter(AuditLog.registry_name == reg.name, AuditLog.outcome == "success")
                   .order_by(AuditLog.id.desc()).first())
        assert entry is not None
        assert entry.key_preview == f"identity:{SUBJECT}"

    def test_claim_rules_are_honoured(self, client, db, binding, signing_key, monkeypatch):
        row, _obj, _reg, _team = binding
        row.claim_rules = {"repository": "acme/payments"}
        db.commit()
        monkeypatch.setattr("aegis.deps.fetch_secrets", lambda rows, auth: {"x": "v"})

        ok = make_token(signing_key, extra={"repository": "acme/payments"})
        assert client.get("/secrets", headers=_headers(ok)).status_code == 200

        wrong = make_token(signing_key, extra={"repository": "acme/other"})
        assert client.get("/secrets", headers=_headers(wrong)).status_code == 401

        missing = make_token(signing_key)
        assert client.get("/secrets", headers=_headers(missing)).status_code == 401

    def test_api_keys_still_work(self, client, db, monkeypatch):
        """The new mechanism must not disturb the old one."""
        from tests.test_secrets import _auth_header, _create_scenario
        obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.deps.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})
        assert client.get("/secrets", headers=_auth_header(key)).status_code == 200


class TestRejectedIdentity:

    @pytest.mark.parametrize("kwargs,why", [
        ({"audience": "someone-else"}, "token minted for another service"),
        ({"issuer": "https://evil.example.com"}, "different issuer"),
        ({"subject": "system:serviceaccount:other:api"}, "unknown subject"),
        ({"exp_delta": -3600}, "expired"),
        ({"nbf_delta": 3600}, "not yet valid"),
    ])
    def test_token_is_refused(self, client, binding, signing_key, kwargs, why):
        token = make_token(signing_key, **kwargs)
        assert client.get("/secrets", headers=_headers(token)).status_code == 401, why

    def test_signature_from_an_unpublished_key_is_refused(self, client, binding, other_key):
        assert client.get("/secrets", headers=_headers(make_token(other_key))).status_code == 401

    def test_tampered_payload_is_refused(self, client, binding, signing_key):
        token = make_token(signing_key)
        header, payload, signature = token.split(".")
        forged = base64url_encode(json.dumps(
            {"iss": ISSUER, "sub": "system:serviceaccount:kube-system:admin",
             "aud": AUDIENCE, "iat": int(time.time()), "exp": int(time.time()) + 300}
        ).encode()).decode().rstrip("=")
        assert client.get("/secrets",
                          headers=_headers(f"{header}.{forged}.{signature}")).status_code == 401

    def test_unsigned_token_is_refused(self, client, binding):
        """alg: none is the oldest JWT attack there is."""
        token = jwt.encode({"iss": ISSUER, "sub": SUBJECT, "aud": AUDIENCE,
                            "iat": int(time.time()), "exp": int(time.time()) + 300},
                           key="", algorithm="none")
        assert client.get("/secrets", headers=_headers(token)).status_code == 401

    def test_hmac_signed_with_the_public_key_is_refused(self, client, binding, signing_key):
        """
        Algorithm confusion: sign HS256 using the issuer's public key as the
        shared secret. A verifier that allows the HMAC family accepts it.
        """
        import hashlib
        import hmac as hmac_mod

        from cryptography.hazmat.primitives import serialization

        pub = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Built by hand: PyJWT refuses to sign HS256 with an asymmetric key,
        # but an attacker is not using PyJWT. The defence has to be in the
        # verifier's algorithm allowlist, not in the signing library.
        header = base64url_encode(json.dumps({"alg": "HS256", "kid": KID}).encode()).decode().rstrip("=")
        payload = base64url_encode(json.dumps(
            {"iss": ISSUER, "sub": SUBJECT, "aud": AUDIENCE,
             "iat": int(time.time()), "exp": int(time.time()) + 300}).encode()).decode().rstrip("=")
        signature = base64url_encode(
            hmac_mod.new(pub, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        token = f"{header}.{payload}.{signature}"

        assert client.get("/secrets", headers=_headers(token)).status_code == 401

    def test_disabled_binding_stops_working(self, client, db, binding, signing_key):
        row, _obj, _reg, _team = binding
        row.enabled = False
        db.commit()
        assert client.get("/secrets", headers=_headers(make_token(signing_key))).status_code == 401

    def test_unknown_issuer_is_refused_without_any_outbound_call(
            self, client, binding, signing_key, monkeypatch):
        def explode(*a, **k):
            raise AssertionError("must not fetch JWKS for an unbound issuer")
        monkeypatch.setattr(identity, "get_jwks", explode)
        token = make_token(signing_key, issuer="https://unbound.example.com")
        assert client.get("/secrets", headers=_headers(token)).status_code == 401

    def test_oversized_token_is_refused(self, binding, signing_key):
        token = make_token(signing_key, extra={"padding": "x" * identity.MAX_TOKEN_BYTES})
        with pytest.raises(identity.IdentityError, match="too large"):
            identity.verify(token, issuer=ISSUER, audience=AUDIENCE)


class TestVerifierUnits:

    def test_only_asymmetric_algorithms_are_allowed(self):
        assert not any(a.startswith("HS") for a in identity.ALLOWED_ALGORITHMS)
        assert "none" not in identity.ALLOWED_ALGORITHMS

    def test_jwt_and_api_keys_are_told_apart(self):
        assert identity.looks_like_jwt("a.b.c")
        assert not identity.looks_like_jwt("sk_abcdefghij")
        assert not identity.looks_like_jwt("sk_a.b.c")

    def test_claim_rules_match_list_claims(self):
        assert identity.claims_match({"groups": ["a", "b"]}, {"groups": "a"})
        assert not identity.claims_match({"groups": ["a"]}, {"groups": "z"})

    def test_absent_claim_never_satisfies_a_rule(self):
        assert not identity.claims_match({}, {"repository": "acme/payments"})

    def test_no_rules_means_no_extra_requirement(self):
        assert identity.claims_match({}, None)
        assert identity.claims_match({}, {})

    def test_jwks_discovery_goes_through_the_url_guard(self, monkeypatch):
        """An issuer URL must not become an SSRF primitive."""
        monkeypatch.setattr("aegis.url_guard.check_url", lambda url: "link-local address")
        with pytest.raises(identity.IdentityError, match="blocked"):
            identity._discover_jwks_uri("http://169.254.169.254")


class TestAdminBindingAPI:
    """Creating a binding grants access to a registry, so it is change-logged."""

    def _payload(self, team, reg, **over):
        body = {"name": _unique("binding"), "issuer": ISSUER, "audience": AUDIENCE,
                "subject": SUBJECT, "team_id": str(team.id), "registry_id": str(reg.id)}
        body.update(over)
        return body

    def test_create_list_update_delete(self, client, db, binding):
        from tests.conftest import ADMIN_CREDS
        _row, _obj, reg, team = binding

        created = client.post("/admin/api/identity-bindings", auth=ADMIN_CREDS,
                              json=self._payload(team, reg, subject="system:serviceaccount:payments:worker"))
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["enabled"] is True
        assert body["registry_name"] == reg.name

        listing = client.get("/admin/api/identity-bindings", auth=ADMIN_CREDS)
        assert listing.status_code == 200
        assert any(b["id"] == body["id"] for b in listing.json()["bindings"])

        updated = client.put(f"/admin/api/identity-bindings/{body['id']}", auth=ADMIN_CREDS,
                             json={"enabled": False})
        assert updated.status_code == 200 and updated.json()["enabled"] is False

        assert client.delete(f"/admin/api/identity-bindings/{body['id']}",
                             auth=ADMIN_CREDS).status_code == 204

    def test_creation_is_change_logged(self, client, db, binding):
        from aegis.models import ChangeLog
        from tests.conftest import ADMIN_CREDS
        _row, _obj, reg, team = binding

        resp = client.post("/admin/api/identity-bindings", auth=ADMIN_CREDS,
                           json=self._payload(team, reg, subject="system:serviceaccount:payments:logged"))
        assert resp.status_code == 201
        entry = (db.query(ChangeLog)
                   .filter(ChangeLog.entity_type == "identity_binding",
                           ChangeLog.entity_id == resp.json()["id"])
                   .first())
        assert entry is not None and entry.action == "created"

    def test_duplicate_is_rejected(self, client, binding):
        from tests.conftest import ADMIN_CREDS
        _row, _obj, reg, team = binding
        body = self._payload(team, reg, subject="system:serviceaccount:payments:dup")
        assert client.post("/admin/api/identity-bindings", auth=ADMIN_CREDS, json=body).status_code == 201
        assert client.post("/admin/api/identity-bindings", auth=ADMIN_CREDS, json=body).status_code == 409

    def test_unknown_team_or_registry_is_rejected(self, client, binding):
        from tests.conftest import ADMIN_CREDS
        _row, _obj, reg, team = binding
        missing = str(uuid.uuid4())
        assert client.post("/admin/api/identity-bindings", auth=ADMIN_CREDS,
                           json=self._payload(team, reg, team_id=missing)).status_code == 404
        assert client.post("/admin/api/identity-bindings", auth=ADMIN_CREDS,
                           json=self._payload(team, reg, registry_id=missing)).status_code == 404

    def test_requires_admin(self, client, binding):
        _row, _obj, reg, team = binding
        assert client.get("/admin/api/identity-bindings").status_code == 401
        assert client.post("/admin/api/identity-bindings",
                           json=self._payload(team, reg)).status_code == 401

    def test_audience_is_mandatory(self, client, binding):
        from tests.conftest import ADMIN_CREDS
        _row, _obj, reg, team = binding
        body = self._payload(team, reg)
        del body["audience"]
        # Without it, a token minted for another service would be accepted.
        assert client.post("/admin/api/identity-bindings", auth=ADMIN_CREDS,
                           json=body).status_code == 422

