"""Tests for empty-endpoint wire #24: GET /api/v1/exec-reporting/ index.

Previously returned items:[] hardcoded. Now returns real list_reports() data.
Multica #4009.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), headers={"Authorization": "Bearer test-token"})


def test_exec_reporting_index_returns_items_key(client):
    """GET / must return an 'items' key (not hardcoded empty list)."""
    resp = client.get("/api/v1/exec-reporting/", params={"org_id": "default"})
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    assert "count" in body
    assert body["count"] == len(body["items"])


def test_exec_reporting_index_count_matches_items(client):
    """count field must always equal len(items) — never a stale hardcoded 0."""
    resp = client.get("/api/v1/exec-reporting/", params={"org_id": "test-org-4009"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == len(body["items"])
    assert body["org_id"] == "test-org-4009"
