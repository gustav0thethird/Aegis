"""
Shared fixtures for Aegis test suite.

Unit tests (test_policy, test_broker, test_rate_limit) require no database.
Integration tests (test_secrets) require PostgreSQL — set TEST_DATABASE_URL or
ensure the default aegis_test database is reachable.

Local dev: run `make test-db` once to create aegis_test in the dev Postgres
           container, then `make test`.
CI:        PostgreSQL service container is provisioned by the workflow.
"""

import os

# ── Must be set before any application module is imported ──────────────────
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://broker:changeme@localhost:5432/aegis_test",
)
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-chars-xyzxyzxy")
os.environ.setdefault("AUTH_PATH", "config/auth.json")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")

import pytest
import fakeredis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

from aegis.database import Base, get_db
import aegis.models  # registers all ORM classes in Base.metadata  # noqa: F401
from aegis import rate_limit

_engine = create_engine(os.environ["DATABASE_URL"])
_Session = sessionmaker(bind=_engine)

# Credentials used in admin API calls throughout the test suite
ADMIN_CREDS = ("admin", "test-admin-pass")


@pytest.fixture(scope="session")
def _schema():
    """Create all tables once per test session; drop afterwards."""
    Base.metadata.drop_all(_engine)
    Base.metadata.create_all(_engine)
    yield
    Base.metadata.drop_all(_engine)


@pytest.fixture(scope="session")
def client(_schema):
    """
    Session-scoped TestClient.

    - Overrides get_db so every request uses a fresh session against aegis_test.
    - Patches rate_limit._client with a FakeRedis instance.
    - Startup events run once (admin user is seeded).
    """
    r = fakeredis.FakeRedis(decode_responses=True)
    rate_limit._client = r

    from aegis.api import app

    def override_db():
        s = _Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_db

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c

    app.dependency_overrides.clear()
    rate_limit._client = None


@pytest.fixture()
def db():
    """Function-scoped session for direct DB setup in integration tests."""
    s = _Session()
    yield s
    s.rollback()
    s.close()
