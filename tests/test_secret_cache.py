"""
Tests for the short-lived brokered-secret cache and the ESO registry gate.

The cache exists so ESO's timer-driven refresh does not hammer the upstream
vault. Because it holds plaintext credentials, the properties that matter are
that it is off unless asked for, that one team's entry can never serve another,
and that revoking a key drops whatever it cached.
"""

import time

import pytest

from aegis import secret_cache
from aegis.keys import hash_key
from aegis.models import TeamRegistryKey
from tests.conftest import ADMIN_CREDS
from tests.test_secrets import _auth_header, _create_scenario


@pytest.fixture(autouse=True)
def clean_cache(monkeypatch):
    for var in ("SECRET_CACHE_TTL_SECONDS", "SECRET_CACHE_MAX_ENTRIES",
                "ESO_ALLOW_REGISTRY_EXTRACT"):
        monkeypatch.delenv(var, raising=False)
    secret_cache.clear()
    yield
    secret_cache.clear()


class TestCacheDefaults:

    def test_disabled_by_default(self):
        """Holding plaintext longer than the request needs is opt-in."""
        assert secret_cache.enabled() is False

    def test_put_is_a_noop_while_disabled(self):
        secret_cache.put("k", {"a": "b"})
        assert secret_cache.get("k") is None

    def test_enabled_by_a_positive_ttl(self, monkeypatch):
        monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", "30")
        assert secret_cache.enabled() is True

    def test_invalid_ttl_falls_back_to_disabled(self, monkeypatch):
        monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", "banana")
        assert secret_cache.enabled() is False


class TestCacheBehaviour:

    @pytest.fixture(autouse=True)
    def ttl(self, monkeypatch):
        monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", "30")

    def test_round_trips(self):
        secret_cache.put("k", {"db": "s3cr3t"})
        assert secret_cache.get("k") == {"db": "s3cr3t"}

    def test_returns_a_copy(self):
        """A caller mutating the result must not corrupt the cache."""
        secret_cache.put("k", {"db": "s3cr3t"})
        got = secret_cache.get("k")
        got["db"] = "tampered"
        assert secret_cache.get("k") == {"db": "s3cr3t"}

    def test_expires(self, monkeypatch):
        monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", "1")
        secret_cache.put("k", {"db": "v"})
        assert secret_cache.get("k") is not None

        real = time.monotonic
        monkeypatch.setattr(secret_cache.time, "monotonic", lambda: real() + 5)
        assert secret_cache.get("k") is None

    def test_keys_are_scoped_per_api_key(self):
        """Two teams must never share an entry, even for the same object."""
        a = secret_cache.make_key("hash-a", "db_password")
        b = secret_cache.make_key("hash-b", "db_password")
        assert a != b

        secret_cache.put(a, {"db_password": "team-a-value"})
        assert secret_cache.get(b) is None

    def test_object_and_registry_scopes_differ(self):
        assert (secret_cache.make_key("h", "db_password")
                != secret_cache.make_key("h", "*"))

    def test_eviction_bounds_the_cache(self, monkeypatch):
        monkeypatch.setenv("SECRET_CACHE_MAX_ENTRIES", "3")
        for i in range(6):
            secret_cache.put(f"k{i}", {"v": str(i)})
        assert secret_cache.stats()["entries"] == 3
        assert secret_cache.get("k0") is None      # oldest evicted
        assert secret_cache.get("k5") is not None

    def test_invalidate_drops_only_that_keys_entries(self):
        secret_cache.put(secret_cache.make_key("hash-a", "one"), {"v": "1"})
        secret_cache.put(secret_cache.make_key("hash-a", "two"), {"v": "2"})
        secret_cache.put(secret_cache.make_key("hash-b", "one"), {"v": "3"})

        assert secret_cache.invalidate("hash-a") == 2
        assert secret_cache.get(secret_cache.make_key("hash-a", "one")) is None
        assert secret_cache.get(secret_cache.make_key("hash-b", "one")) is not None


class TestEsoCaching:

    def test_second_fetch_skips_the_vault(self, client, db, monkeypatch):
        monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", "30")
        obj, _reg, _team, key = _create_scenario(db, client)
        calls = []

        def _fetch(rows, auth):
            calls.append(1)
            return {rows[0]["name"]: "v"}

        monkeypatch.setattr("aegis.deps.fetch_secrets", _fetch)

        first = client.get(f"/eso/v1/secret/{obj.name}", headers=_auth_header(key))
        second = client.get(f"/eso/v1/secret/{obj.name}", headers=_auth_header(key))

        assert first.json() == second.json()
        assert len(calls) == 1, "the second fetch hit the vault again"

    def test_a_cache_hit_is_still_audited(self, client, db, monkeypatch):
        """A cached read is still a read, and must appear in the audit log."""
        from aegis.models import AuditLog

        monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", "30")
        obj, _reg, team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.deps.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})

        client.get(f"/eso/v1/secret/{obj.name}", headers=_auth_header(key))
        before = db.query(AuditLog).filter(AuditLog.team_name == team.name).count()
        client.get(f"/eso/v1/secret/{obj.name}", headers=_auth_header(key))
        after = db.query(AuditLog).filter(AuditLog.team_name == team.name).count()

        assert after == before + 1

    def test_secrets_endpoint_is_never_cached(self, client, db, monkeypatch):
        """The change-controlled path must reach the vault every time."""
        monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", "30")
        _obj, _reg, _team, key = _create_scenario(db, client)
        calls = []
        monkeypatch.setattr("aegis.deps.fetch_secrets",
                            lambda rows, auth: calls.append(1) or {"x": "v"})

        client.get("/secrets", headers=_auth_header(key))
        client.get("/secrets", headers=_auth_header(key))

        assert len(calls) == 2

    def test_revoking_a_key_drops_its_cache(self, client, db, monkeypatch):
        monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", "30")
        obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.deps.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})

        client.get(f"/eso/v1/secret/{obj.name}", headers=_auth_header(key))
        row = db.query(TeamRegistryKey).filter_by(key_hash=hash_key(key)).one()
        assert secret_cache.get(secret_cache.make_key(row.key_hash, obj.name)) is not None

        secret_cache.invalidate(row.key_hash)
        assert secret_cache.get(secret_cache.make_key(row.key_hash, obj.name)) is None


class TestRegistryExtractGate:

    def test_allowed_by_default(self, client, db, monkeypatch):
        _obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.deps.fetch_secrets", lambda rows, auth: {"x": "v"})
        assert client.get("/eso/v1/secrets", headers=_auth_header(key)).status_code == 200

    def test_can_be_disabled(self, client, db, monkeypatch):
        monkeypatch.setenv("ESO_ALLOW_REGISTRY_EXTRACT", "false")
        _obj, _reg, _team, key = _create_scenario(db, client)

        resp = client.get("/eso/v1/secrets", headers=_auth_header(key))

        assert resp.status_code == 403
        assert "individually" in resp.json()["detail"]

    def test_per_object_still_works_when_disabled(self, client, db, monkeypatch):
        monkeypatch.setenv("ESO_ALLOW_REGISTRY_EXTRACT", "false")
        obj, _reg, _team, key = _create_scenario(db, client)
        monkeypatch.setattr("aegis.deps.fetch_secrets",
                            lambda rows, auth: {rows[0]["name"]: "v"})

        resp = client.get(f"/eso/v1/secret/{obj.name}", headers=_auth_header(key))
        assert resp.status_code == 200

    def test_admin_endpoints_are_unaffected(self, client):
        assert client.get("/admin/api/ping", auth=ADMIN_CREDS).status_code == 200
