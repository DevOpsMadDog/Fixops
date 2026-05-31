"""Tests for alert_correlation_router — Multica #3756.

Uses a temporary SQLite database per test via the ALERT_CORRELATION_DB_PATH
environment variable + module-level singleton reset between tests.

Coverage (8+ tests):
  1.  info-200
  2.  list-empty
  3.  post-create-and-roundtrip-via-get
  4.  get-404-for-missing
  5.  put-partial-update
  6.  put-404-for-missing
  7.  delete-and-verify-404
  8.  401-on-missing-X-API-Key
  9.  post-invalid-action-422
  10. list-scoped-to-org-id
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers to isolate the module-level DB singleton between tests
# ---------------------------------------------------------------------------


def _build_app(db_path: str) -> FastAPI:
    """Build a fresh FastAPI app with the router wired to *db_path*."""
    # Patch env before import so _get_db() picks the tmp path
    os.environ["ALERT_CORRELATION_DB_PATH"] = db_path

    # Force a fresh import of the router module so the module-level _db
    # singleton is reset.
    mod_name = "apps.api.alert_correlation_router"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    import apps.api.alert_correlation_router as acr  # noqa: PLC0415

    # Also reset the module-level singleton
    acr._db = None  # type: ignore[attr-defined]

    app = FastAPI()
    # Mount with a real api_key_auth bypass for tests:
    # Override the dependency so tests don't need real keys
    from apps.api.auth_deps import api_key_auth  # noqa: PLC0415

    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(acr.router)
    return app


@pytest.fixture()
def client(tmp_path: Path) -> Generator[TestClient, None, None]:
    db_path = str(tmp_path / "test_corr.db")
    app = _build_app(db_path)
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Test 1 — GET / returns 200 with expected structure
# ---------------------------------------------------------------------------


def test_info_200(client: TestClient) -> None:
    resp = client.get("/api/v1/alert-mgmt/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Alert Correlation Rules"
    assert body["rule_count"] == 0
    assert body["enabled_count"] == 0
    assert body["status"] == "empty"
    assert isinstance(body["endpoints"], list)
    assert len(body["endpoints"]) >= 5


# ---------------------------------------------------------------------------
# Test 2 — GET /rules returns empty list
# ---------------------------------------------------------------------------


def test_list_empty(client: TestClient) -> None:
    resp = client.get("/api/v1/alert-mgmt/rules", params={"org_id": "org-a"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["rules"] == []
    assert body["count"] == 0


# ---------------------------------------------------------------------------
# Test 3 — POST /rules creates rule, GET /rules/{id} roundtrips it
# ---------------------------------------------------------------------------


def test_create_and_get_roundtrip(client: TestClient) -> None:
    payload = {
        "org_id": "org-b",
        "name": "Cluster CVE-2024-1234",
        "match_field": "cve_id",
        "match_value": "CVE-2024-1234",
        "window_secs": 600,
        "suppress_secs": 120,
        "action": "group",
    }
    create_resp = client.post("/api/v1/alert-mgmt/rules", json=payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["id"] != ""
    assert created["org_id"] == "org-b"
    assert created["name"] == "Cluster CVE-2024-1234"
    assert created["match_field"] == "cve_id"
    assert created["match_value"] == "CVE-2024-1234"
    assert created["window_secs"] == 600
    assert created["suppress_secs"] == 120
    assert created["action"] == "group"
    assert created["enabled"] == 1
    assert "created_at" in created
    assert "updated_at" in created

    # Roundtrip via GET
    get_resp = client.get(f"/api/v1/alert-mgmt/rules/{created['id']}")
    assert get_resp.status_code == 200
    fetched = get_resp.json()
    assert fetched["id"] == created["id"]
    assert fetched["name"] == "Cluster CVE-2024-1234"


# ---------------------------------------------------------------------------
# Test 4 — GET /rules/{rule_id} returns 404 for unknown id
# ---------------------------------------------------------------------------


def test_get_404_for_missing(client: TestClient) -> None:
    resp = client.get("/api/v1/alert-mgmt/rules/00000000-dead-beef-0000-000000000000")
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "rule_not_found"


# ---------------------------------------------------------------------------
# Test 5 — PUT /rules/{rule_id} partially updates the rule
# ---------------------------------------------------------------------------


def test_put_partial_update(client: TestClient) -> None:
    # Create a rule first
    created = client.post(
        "/api/v1/alert-mgmt/rules",
        json={
            "org_id": "org-c",
            "name": "Original Name",
            "match_field": "source_tool",
            "action": "suppress",
        },
    ).json()
    rule_id = created["id"]

    # Partial update: change name + window_secs
    update_resp = client.put(
        f"/api/v1/alert-mgmt/rules/{rule_id}",
        json={"name": "Updated Name", "window_secs": 900},
    )
    assert update_resp.status_code == 200
    updated = update_resp.json()
    assert updated["name"] == "Updated Name"
    assert updated["window_secs"] == 900
    # Unchanged fields preserved
    assert updated["action"] == "suppress"
    assert updated["match_field"] == "source_tool"
    # updated_at must be >= created_at
    assert updated["updated_at"] >= created["created_at"]


# ---------------------------------------------------------------------------
# Test 6 — PUT /rules/{rule_id} returns 404 for unknown id
# ---------------------------------------------------------------------------


def test_put_404_for_missing(client: TestClient) -> None:
    resp = client.put(
        "/api/v1/alert-mgmt/rules/00000000-dead-beef-0000-000000000001",
        json={"name": "ghost"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "rule_not_found"


# ---------------------------------------------------------------------------
# Test 7 — DELETE /rules/{rule_id} removes rule; subsequent GET returns 404
# ---------------------------------------------------------------------------


def test_delete_and_verify_404(client: TestClient) -> None:
    created = client.post(
        "/api/v1/alert-mgmt/rules",
        json={
            "org_id": "org-d",
            "name": "Doomed Rule",
            "match_field": "asset_id",
            "action": "escalate",
        },
    ).json()
    rule_id = created["id"]

    del_resp = client.delete(f"/api/v1/alert-mgmt/rules/{rule_id}")
    assert del_resp.status_code == 204

    get_resp = client.get(f"/api/v1/alert-mgmt/rules/{rule_id}")
    assert get_resp.status_code == 404


# ---------------------------------------------------------------------------
# Test 8 — 401 on missing X-API-Key (auth is enforced by real dep)
# ---------------------------------------------------------------------------


def test_401_on_missing_api_key(tmp_path: Path) -> None:
    """Build an app WITHOUT overriding api_key_auth to verify auth is wired."""
    db_path = str(tmp_path / "test_auth.db")
    os.environ["ALERT_CORRELATION_DB_PATH"] = db_path

    mod_name = "apps.api.alert_correlation_router"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import apps.api.alert_correlation_router as acr  # noqa: PLC0415

    acr._db = None  # type: ignore[attr-defined]

    # Build app WITHOUT overriding the auth dep
    app = FastAPI()
    app.include_router(acr.router)

    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/api/v1/alert-mgmt/rules")
        # api_key_auth raises 401 when no key provided
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test 9 — POST /rules with invalid action returns 422
# ---------------------------------------------------------------------------


def test_post_invalid_action_422(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/alert-mgmt/rules",
        json={
            "org_id": "org-e",
            "name": "Bad Action Rule",
            "match_field": "cve_id",
            "action": "delete_everything",
        },
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_action"


# ---------------------------------------------------------------------------
# Test 10 — GET /rules scoped correctly by org_id
# ---------------------------------------------------------------------------


def test_list_scoped_to_org_id(client: TestClient) -> None:
    # Create rules for two different orgs
    client.post(
        "/api/v1/alert-mgmt/rules",
        json={"org_id": "org-x", "name": "Rule X", "match_field": "cve_id", "action": "group"},
    )
    client.post(
        "/api/v1/alert-mgmt/rules",
        json={"org_id": "org-y", "name": "Rule Y", "match_field": "cve_id", "action": "group"},
    )

    resp_x = client.get("/api/v1/alert-mgmt/rules", params={"org_id": "org-x"})
    assert resp_x.status_code == 200
    assert resp_x.json()["count"] == 1
    assert resp_x.json()["rules"][0]["name"] == "Rule X"

    resp_y = client.get("/api/v1/alert-mgmt/rules", params={"org_id": "org-y"})
    assert resp_y.status_code == 200
    assert resp_y.json()["count"] == 1
    assert resp_y.json()["rules"][0]["name"] == "Rule Y"
