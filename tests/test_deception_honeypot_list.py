"""Tests for DeceptionEngine.list_honeypot_endpoints + GET /api/v1/deception/honeypots.

6 tests:
  1. list_honeypot_endpoints returns empty list when no endpoints registered
  2. list_honeypot_endpoints returns deployed endpoints for the correct org
  3. list_honeypot_endpoints respects active_only=True (excludes inactive via direct DB update)
  4. list_honeypot_endpoints active_only=False returns all including inactive
  5. list_honeypot_endpoints enforces org isolation
  6. GET /api/v1/deception/honeypots returns 200 with deployed endpoints via HTTP
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from core.deception_engine import DeceptionEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return DeceptionEngine(db_path=str(tmp_path / "hp_list_test.db"))


@pytest.fixture
def org():
    return "org-honeypot"


@pytest.fixture
def org2():
    return "org-other"


# ---------------------------------------------------------------------------
# Engine-level tests
# ---------------------------------------------------------------------------

def test_list_honeypot_endpoints_empty(engine, org):
    """Returns empty list when no endpoints have been deployed."""
    result = engine.list_honeypot_endpoints(org_id=org)
    assert result == []


def test_list_honeypot_endpoints_returns_deployed(engine, org):
    """Returns the endpoint that was just deployed."""
    deployed = engine.deploy_honeypot_endpoint(path="/admin/secret", org_id=org)
    result = engine.list_honeypot_endpoints(org_id=org)

    assert len(result) == 1
    ep = result[0]
    assert ep["id"] == deployed["id"]
    assert ep["path"] == "/admin/secret"
    assert ep["org_id"] == org
    assert ep["active"] is True
    assert ep["created_at"] == deployed["created_at"]


def test_list_honeypot_endpoints_active_only_excludes_inactive(engine, org):
    """active_only=True (default) hides endpoints deactivated in DB."""
    engine.deploy_honeypot_endpoint(path="/trap/one", org_id=org)
    engine.deploy_honeypot_endpoint(path="/trap/two", org_id=org)

    # Deactivate /trap/one directly via DB (engine has no deactivate method yet)
    with sqlite3.connect(engine.db_path) as conn:
        conn.execute(
            "UPDATE honeypot_endpoints SET active = 0 WHERE path = ? AND org_id = ?",
            ("/trap/one", org),
        )

    active = engine.list_honeypot_endpoints(org_id=org, active_only=True)
    assert len(active) == 1
    assert active[0]["path"] == "/trap/two"


def test_list_honeypot_endpoints_active_only_false_returns_all(engine, org):
    """active_only=False returns both active and inactive endpoints."""
    engine.deploy_honeypot_endpoint(path="/trap/a", org_id=org)
    engine.deploy_honeypot_endpoint(path="/trap/b", org_id=org)

    with sqlite3.connect(engine.db_path) as conn:
        conn.execute(
            "UPDATE honeypot_endpoints SET active = 0 WHERE path = ? AND org_id = ?",
            ("/trap/a", org),
        )

    all_eps = engine.list_honeypot_endpoints(org_id=org, active_only=False)
    paths = {ep["path"] for ep in all_eps}
    assert "/trap/a" in paths
    assert "/trap/b" in paths


def test_list_honeypot_endpoints_org_isolation(engine, org, org2):
    """Endpoints for org2 are not visible to org."""
    engine.deploy_honeypot_endpoint(path="/secret/org2", org_id=org2)
    result = engine.list_honeypot_endpoints(org_id=org)
    assert result == []


# ---------------------------------------------------------------------------
# HTTP-level test
# ---------------------------------------------------------------------------

def test_get_honeypots_http_returns_deployed(tmp_path):
    """GET /api/v1/deception/honeypots returns 200 with registered endpoints."""
    from fastapi import FastAPI
    from apps.api.auth_deps import api_key_auth
    from apps.api.deception_router import router, _get_engine

    # Wire an isolated engine for this test
    isolated_engine = DeceptionEngine(db_path=str(tmp_path / "http_hp_test.db"))
    isolated_engine.deploy_honeypot_endpoint(path="/fake/admin", org_id="test-org")

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_get_engine] = lambda: isolated_engine
    app.dependency_overrides[api_key_auth] = lambda: None  # bypass auth

    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get(
        "/api/v1/deception/honeypots",
        params={"org_id": "test-org"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["path"] == "/fake/admin"
    assert data[0]["active"] is True
