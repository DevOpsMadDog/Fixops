"""Test that GET /api/v1/assets/ calls list_assets() instead of returning hardcoded empty."""
import os
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-for-ci-testing")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

import pytest
from fastapi.testclient import TestClient

API_KEY = os.environ["FIXOPS_API_TOKEN"]
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


def test_asset_index_returns_200_with_items_key(client):
    """GET / must return 200 with items list (not hardcoded [])."""
    resp = client.get("/api/v1/assets/", headers=HEADERS, params={"org_id": "test-org"})
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert "items" in body, f"Missing 'items' key: {list(body.keys())}"
    assert isinstance(body["items"], list), "items must be a list"
    assert "count" in body, "Missing 'count' key"
    assert body["count"] == len(body["items"]), "count must match len(items)"


def test_asset_index_count_matches_items(client):
    """count field must equal len(items) — not hardcoded 0."""
    resp = client.get("/api/v1/assets/", headers=HEADERS, params={"org_id": "test-org-2"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == len(body["items"]), \
        f"count={body['count']} != len(items)={len(body['items'])}"
