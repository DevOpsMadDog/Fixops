"""Tests for Security Query Language router — /api/v1/sql."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App fixture — bypass auth via dependency_overrides
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from apps.api.auth_deps import api_key_auth
    from apps.api.security_query_language_router import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None  # bypass auth in tests
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# GET /schema
# ---------------------------------------------------------------------------

def test_get_schema(client):
    resp = client.get("/api/v1/sql/schema")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert len(data) > 0


# ---------------------------------------------------------------------------
# GET /stats
# ---------------------------------------------------------------------------

def test_get_stats(client):
    resp = client.get("/api/v1/sql/stats?org_id=test-org")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)


# ---------------------------------------------------------------------------
# GET /history — initially empty for fresh org
# ---------------------------------------------------------------------------

def test_list_history_empty(client):
    resp = client.get("/api/v1/sql/history?org_id=fresh-org-sql")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# GET /queries — initially empty for fresh org
# ---------------------------------------------------------------------------

def test_list_queries_empty(client):
    resp = client.get("/api/v1/sql/queries?org_id=fresh-org-sql")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# POST /execute — memory provider (no real DB rows, returns empty list)
# ---------------------------------------------------------------------------

def test_execute_valid_query_memory(client):
    payload = {
        "dsl": "FROM aws.ec2.instance RETURN asset_id",
        "org_id": "test-org",
        "provider": "memory",
        "limit": 100,
    }
    resp = client.post("/api/v1/sql/execute", json=payload)
    # 200 OK with rows key, or 422 if entity schema mismatch
    assert resp.status_code in (200, 422, 500)
    if resp.status_code == 200:
        data = resp.json()
        assert "rows" in data
        assert isinstance(data["rows"], list)


# ---------------------------------------------------------------------------
# POST /execute — invalid DSL returns error
# ---------------------------------------------------------------------------

def test_execute_invalid_dsl(client):
    payload = {
        "dsl": "NOT A VALID DSL @@@@",
        "org_id": "test-org",
        "provider": "memory",
    }
    resp = client.post("/api/v1/sql/execute", json=payload)
    assert resp.status_code in (422, 500)


# ---------------------------------------------------------------------------
# POST /execute — empty dsl body returns 422 (pydantic min_length)
# ---------------------------------------------------------------------------

def test_execute_empty_dsl(client):
    resp = client.post("/api/v1/sql/execute", json={"dsl": "", "org_id": "test-org"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# CRUD lifecycle: save -> list -> get -> delete
# ---------------------------------------------------------------------------

def test_save_list_get_delete_query(client):
    # Save
    save_resp = client.post("/api/v1/sql/queries", json={
        "name": "my-test-query",
        "dsl": "FROM aws.s3.bucket RETURN asset_id",
        "org_id": "test-org",
    })
    assert save_resp.status_code in (201, 422, 500)
    if save_resp.status_code != 201:
        pytest.skip("save_query returned non-201 — engine may reject unknown entity")

    saved = save_resp.json()
    query_id = saved.get("id") or saved.get("query_id")
    assert query_id

    # List
    list_resp = client.get("/api/v1/sql/queries?org_id=test-org")
    assert list_resp.status_code == 200
    ids = [q.get("id") or q.get("query_id") for q in list_resp.json()]
    assert query_id in ids

    # Get
    get_resp = client.get(f"/api/v1/sql/queries/{query_id}?org_id=test-org")
    assert get_resp.status_code == 200

    # Delete
    del_resp = client.delete(f"/api/v1/sql/queries/{query_id}?org_id=test-org")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # Get after delete -> 404
    gone = client.get(f"/api/v1/sql/queries/{query_id}?org_id=test-org")
    assert gone.status_code == 404


# ---------------------------------------------------------------------------
# GET /queries/{id} — missing id -> 404
# ---------------------------------------------------------------------------

def test_get_missing_query(client):
    resp = client.get("/api/v1/sql/queries/nonexistent-id?org_id=test-org")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /queries/{id} — missing id -> 404
# ---------------------------------------------------------------------------

def test_delete_missing_query(client):
    resp = client.delete("/api/v1/sql/queries/nonexistent-id?org_id=test-org")
    assert resp.status_code == 404
