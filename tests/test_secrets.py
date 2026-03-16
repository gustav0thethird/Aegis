"""
Integration tests for GET /secrets — the core fetch endpoint.

These tests require a live PostgreSQL database (aegis_test).
All external vault calls (vault_get, aws_get, etc.) are mocked via monkeypatch.
"""

import hashlib
import secrets as slib


from aegis.models import Object, Registry, RegistryObject, Team, TeamRegistryKey
from tests.conftest import ADMIN_CREDS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unique(prefix: str) -> str:
    return f"{prefix}_{slib.token_hex(4)}"


def _create_scenario(db, client):
    """
    Build a minimal working scenario:
      Object → Registry → Team → assignment (returns plaintext API key)

    Object/Registry/Team are inserted directly via the DB session.
    The team-registry assignment is made via the admin API so the
    plaintext key is returned (it's never stored in the DB).
    """
    obj = Object(
        name=_unique("obj"), vendor="vault", auth_ref="prod",
        path="secret/test", created_by="test",
    )
    reg = Registry(name=_unique("reg"), created_by="test")
    db.add(obj)
    db.add(reg)
    db.flush()
    db.add(RegistryObject(registry_id=reg.id, object_name=obj.name))

    team = Team(name=_unique("team"), created_by="test")
    db.add(team)
    db.commit()

    resp = client.post(
        f"/admin/api/teams/{team.id}/registries/{reg.id}",
        auth=ADMIN_CREDS,
    )
    assert resp.status_code == 201, resp.text
    plaintext_key = resp.json()["new_key"]["key"]

    return obj, reg, team, plaintext_key


def _auth_header(key: str) -> dict:
    return {"Authorization": f"Bearer {key}", "X-Change-Number": "CHG-TEST-001"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSecretsEndpoint:

    def test_no_api_key_returns_401(self, client):
        resp = client.get("/secrets")
        assert resp.status_code == 401

    def test_invalid_api_key_returns_401(self, client):
        resp = client.get("/secrets", headers={"Authorization": "Bearer sk_invalid"})
        assert resp.status_code == 401

    def test_happy_path_returns_fetched_secrets(self, client, db, monkeypatch):
        obj, reg, team, key = _create_scenario(db, client)

        monkeypatch.setattr(
            "aegis.api.fetch_secrets",
            lambda rows, auth: {rows[0]["name"]: "plaintext_value"},
        )

        resp = client.get("/secrets", headers=_auth_header(key))

        assert resp.status_code == 200
        assert resp.json() == {obj.name: "plaintext_value"}

    def test_suspended_key_returns_401(self, client, db):
        obj, reg, team, key = _create_scenario(db, client)

        key_hash = hashlib.sha256(key.encode()).hexdigest()
        key_row = db.query(TeamRegistryKey).filter_by(key_hash=key_hash).first()
        key_row.suspended = True
        db.commit()

        resp = client.get("/secrets", headers=_auth_header(key))
        assert resp.status_code == 401

    def test_ip_not_in_allowlist_returns_403(self, client, db):
        obj, reg, team, key = _create_scenario(db, client)

        # TestClient source IP is 127.0.0.1; restrict to a different range
        resp = client.put(
            f"/admin/api/teams/{team.id}/policy",
            json={"ip_allowlist": ["192.168.99.0/24"]},
            auth=ADMIN_CREDS,
        )
        assert resp.status_code == 200

        resp = client.get("/secrets", headers=_auth_header(key))
        assert resp.status_code == 403
        assert "allowlist" in resp.json()["detail"].lower()

    def test_missing_change_number_returns_403(self, client, db):
        obj, reg, team, key = _create_scenario(db, client)
        # change_number_required defaults to True; omit the header
        resp = client.get("/secrets", headers={"Authorization": f"Bearer {key}"})
        assert resp.status_code == 403
        assert "change" in resp.json()["detail"].lower()

    def test_rate_limited_returns_429(self, client, db, monkeypatch):
        obj, reg, team, key = _create_scenario(db, client)

        monkeypatch.setattr(
            "aegis.api.fetch_secrets",
            lambda rows, auth: {rows[0]["name"]: "val"},
        )

        # Cap this registry at 1 rpm
        resp = client.put(
            f"/admin/api/registries/{reg.id}/policy",
            json={"rate_limit_rpm": 1},
            auth=ADMIN_CREDS,
        )
        assert resp.status_code == 200

        r1 = client.get("/secrets", headers=_auth_header(key))
        assert r1.status_code == 200

        r2 = client.get("/secrets", headers=_auth_header(key))
        assert r2.status_code == 429

    def test_successful_fetch_writes_audit_log(self, client, db, monkeypatch):
        from aegis.models import AuditLog

        obj, reg, team, key = _create_scenario(db, client)

        monkeypatch.setattr(
            "aegis.api.fetch_secrets",
            lambda rows, auth: {rows[0]["name"]: "val"},
        )

        client.get("/secrets", headers=_auth_header(key))

        # Use a fresh query to see the committed audit row
        log = (
            db.query(AuditLog)
            .filter_by(team_name=team.name)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.outcome == "success"
        assert log.change_number == "CHG-TEST-001"

    def test_denied_fetch_writes_audit_log(self, client, db):
        from aegis.models import AuditLog

        obj, reg, team, key = _create_scenario(db, client)

        # Trigger a denial via IP allowlist
        client.put(
            f"/admin/api/teams/{team.id}/policy",
            json={"ip_allowlist": ["10.0.0.0/8"]},
            auth=ADMIN_CREDS,
        )

        client.get("/secrets", headers=_auth_header(key))

        log = (
            db.query(AuditLog)
            .filter_by(team_name=team.name)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.outcome == "denied"
