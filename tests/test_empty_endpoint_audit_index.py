"""Tests for wired audit index endpoint — was returning hardcoded items: []."""
from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

_API_KEY = "test-audit-index-key-x6"
os.environ["FIXOPS_API_TOKEN"] = _API_KEY
_HEADERS = {"X-API-Key": _API_KEY}


@pytest.fixture(scope="module")
def client():
    os.environ["FIXOPS_API_TOKEN"] = _API_KEY
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


def test_audit_index_200(client):
    """GET /api/v1/audit/ returns 200 with real structure (not 404/500)."""
    resp = client.get("/api/v1/audit/", headers=_HEADERS)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:200]}"


def test_audit_index_shape(client):
    """GET /api/v1/audit/ returns dict with router, items (list), count keys — items wired from AuditDB.list_audit_logs."""
    resp = client.get("/api/v1/audit/", headers=_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "router" in data
    assert data["router"] == "audit"
    assert "items" in data
    assert isinstance(data["items"], list)
    assert "count" in data
    assert data["count"] == len(data["items"])
