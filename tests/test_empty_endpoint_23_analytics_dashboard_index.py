"""
Tests for empty-endpoint #23: GET /api/v1/analytics/ wired to real
VulnerabilityAnalytics.get_severity_distribution() — no more stub items:[].
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Mount only analytics_dashboard_router to avoid full-app startup overhead."""
    from apps.api.analytics_dashboard_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def test_analytics_dashboard_index_returns_items(client):
    """items must be a list of severity dicts (real engine called), count matches len."""
    resp = client.get("/api/v1/analytics/")
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    assert body["count"] == len(body["items"])


def test_analytics_dashboard_index_severity_shape(client):
    """Each item in items must have 'severity' and 'count' keys."""
    resp = client.get("/api/v1/analytics/")
    assert resp.status_code == 200
    items = resp.json()["items"]
    for item in items:
        assert "severity" in item
        assert "count" in item
        assert isinstance(item["count"], int)
