"""
Integration tests for the External Secrets Operator provider endpoints.

Requires PostgreSQL (aegis_test). Vault calls are mocked.

These endpoints are a response shape for ESO, not a second way in: they must
authenticate, enforce policy, audit and honour revocation exactly as /secrets
does. Most of what is asserted here is that they are no weaker.
"""

import hashlib

from aegis.models import AuditLog, TeamRegistryKey
from tests.conftest import ADMIN_CREDS
from tests.test_secrets import _auth_header, _create_scenario

ALL = "/eso/v1/secrets"


def _one(name):
    return f"/eso/v1/secret/{name}"


class TestEsoAuthentication:

    def test_no_key_returns_401(self, client):
        assert client.get(ALL).status_code == 401
        assert client.get(_one("anything")).status_code == 401

    def test_invalid_key_returns_401(self, client):
        headers = {"Authorization": "Bearer sk_invalid", "X-Change-Number": "CHG-1"}
        assert client.get(ALL, headers=headers).status_code == 401
        assert client.get(_one("x"), headers=headers).status_code == 401

    def test_suspended_key_returns_401(self, client, db):
        _obj, _reg, _team, key = _create_scenario(db, client)

        key_hash = hashlib.sha256(key.encode()).hexdigest()
        db.query(TeamRegistryKey).filter_by(key_hash=key_hash).first().suspended = True
        db.commit()

        assert client.get(ALL, headers=_auth_header(key)).status_code == 401

    def test_revoked_key_returns_401(self, client, db):
        from datetime import datetime, timezone

        _obj, _reg, _team, key = _create_scenario(db, client)

        key_hash = hashlib.sha256(key.encode()).hexdigest()
        row = db.query(TeamRegistryKey).filter_by(key_hash=key_hash).first()
        row.revoked_at = datetime.now(timezone.utc)
        db.commit()

        assert client.get(ALL, headers=_auth_header(key)).status_code == 401


class TestEsoPolicyParity:
    """Policy is enforced by the same code path as /secrets, so it must apply here."""

    def test_missing_change_number_returns_403(self, client, db):
        _obj, _reg, _team, key = _create_scenario(db, client)
        resp = client.get(ALL, headers={"Authorization": f"Bearer {key}"})
        assert resp.status_code == 403
        assert "change" in resp.json()["detail"].lower()

    def test_ip_allowlist_is_enforced(self, client, db):
        _obj, _reg, team, key = _create_scenario(db, client)

        resp = client.put(
            f"/admin/api/teams/{team.id}/policy",
            json={"ip_allowlist": ["192.168.99.0/24"]},
            auth=ADMIN_CREDS,
        )
        assert resp.status_code == 200

        assert client.get(ALL, headers=_auth_header(key)).status_code == 403


class TestEsoFetchAll:

    def test_returns_registry_under_data_key(self, client, db, monkeypatch):
        """ESO dataFrom.extract reads the map at jsonPath $.data."""
        obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "plaintext_value"})

        resp = client.get(ALL, headers=_auth_header(key))

        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == {obj.name: "plaintext_value"}

    def test_includes_team_and_registry_for_traceability(self, client, db, monkeypatch):
        _obj, reg, team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})

        body = client.get(ALL, headers=_auth_header(key)).json()

        assert body["registry"] == reg.name
        assert body["team"] == team.name


class TestEsoFetchOne:

    def test_returns_single_value(self, client, db, monkeypatch):
        """ESO data[].remoteRef reads the scalar at jsonPath $.value."""
        obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "plaintext_value"})

        resp = client.get(_one(obj.name), headers=_auth_header(key))

        assert resp.status_code == 200
        assert resp.json() == {"key": obj.name, "value": "plaintext_value"}

    def test_object_outside_the_registry_returns_404(self, client, db, monkeypatch):
        _obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})

        resp = client.get(_one("not-in-this-registry"), headers=_auth_header(key))

        assert resp.status_code == 404
        # The message must not confirm whether the object exists elsewhere.
        assert resp.json()["detail"] == "Secret not found"

    def test_only_the_requested_object_is_fetched_from_the_vault(self, client, db, monkeypatch):
        """A single-key lookup must not pull the whole registry out of the vault."""
        obj, _reg, _team, key = _create_scenario(db, client)
        seen = {}

        def _fetch(rows, auth):
            seen["names"] = [r["name"] for r in rows]
            return {r["name"]: "v" for r in rows}

        monkeypatch.setattr("aegis.api.fetch_secrets", _fetch)
        client.get(_one(obj.name), headers=_auth_header(key))

        assert seen["names"] == [obj.name]

    def test_denied_lookup_is_audited(self, client, db, monkeypatch):
        _obj, _reg, team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})

        client.get(_one("nope"), headers=_auth_header(key))

        entry = db.query(AuditLog).filter(
            AuditLog.team_name == team.name,
            AuditLog.outcome == "denied",
        ).order_by(AuditLog.timestamp.desc()).first()

        assert entry is not None
        assert "nope" in (entry.error_detail or "")


class TestEsoAuditing:

    def test_successful_fetch_is_audited(self, client, db, monkeypatch):
        _obj, reg, team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.api.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})

        client.get(ALL, headers=_auth_header(key))

        entry = db.query(AuditLog).filter(
            AuditLog.team_name == team.name,
            AuditLog.registry_name == reg.name,
            AuditLog.outcome == "success",
        ).order_by(AuditLog.timestamp.desc()).first()

        assert entry is not None
        assert entry.event == "secrets.fetched"
