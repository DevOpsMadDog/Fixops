"""Test #25: wire GET /api/v1/api-security-engine/ to list_endpoints()."""
import os
import pytest
from fastapi.testclient import TestClient

_API_KEY = os.getenv("FIXOPS_API_TOKEN", "test-token")


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), headers={"X-API-Key": _API_KEY})


def test_api_security_index_returns_items_key(client):
    """Index must return items list (not hardcoded [])."""
    resp = client.get("/api/v1/api-security-engine/", params={"org_id": "test-org"})
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    assert "count" in body
    assert body["count"] == len(body["items"])


def test_api_security_index_count_reflects_real_data(client):
    """count field must match len(items) — not hard-coded 0."""
    resp = client.get("/api/v1/api-security-engine/", params={"org_id": "test-org"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == len(body["items"]), "count must mirror items length"
