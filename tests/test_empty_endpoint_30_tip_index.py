"""Test #30: GET /api/v1/tip/ wired to ThreatIntelPlatformEngine.list_sources()."""
from __future__ import annotations

import os
import pytest

_API_KEY = "test-tip-index-key-x30"
os.environ["FIXOPS_API_TOKEN"] = _API_KEY
_HEADERS = {"X-API-Key": _API_KEY}


@pytest.fixture(scope="module")
def client():
    os.environ["FIXOPS_API_TOKEN"] = _API_KEY
    from apps.api.app import create_app
    from fastapi.testclient import TestClient
    return TestClient(create_app(), raise_server_exceptions=False)


def test_tip_index_returns_200(client):
    """GET /api/v1/tip/ returns 200 — not 404/500."""
    r = client.get("/api/v1/tip/", headers=_HEADERS)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"


def test_tip_index_items_and_count_wired(client):
    """items is a real list from list_sources(); count == len(items)."""
    r = client.get("/api/v1/tip/", headers=_HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data, f"Missing 'items': {data}"
    assert "count" in data, f"Missing 'count': {data}"
    assert "stats" in data, f"Missing 'stats': {data}"
    assert isinstance(data["items"], list)
    assert data["count"] == len(data["items"])
