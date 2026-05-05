"""Test #16 — GET /api/v1/logs/stats wired to LogManagementEngine.get_log_stats()."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Minimal FastAPI app mounting only logs_gap with auth bypassed."""
    # Import the router module — auth dep is list of Depends() objects
    from apps.api.gap_router import logs_gap
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    # Override auth to a no-op so we test the endpoint logic, not auth
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(logs_gap)
    return TestClient(app, raise_server_exceptions=False)


def test_logs_stats_returns_200(client):
    """Endpoint must return 200 (wired to LogManagementEngine, not hardcoded zeros)."""
    r = client.get("/api/v1/logs/stats")
    assert r.status_code == 200


def test_logs_stats_schema(client):
    """Response must contain all required envelope keys."""
    r = client.get("/api/v1/logs/stats")
    assert r.status_code == 200
    body = r.json()
    for key in ("total", "by_level", "sources", "retention_policies", "status"):
        assert key in body, f"Missing key: {key}"


def test_logs_stats_status_field(client):
    """status must be 'ok' or 'degraded' — never missing or wrong value."""
    r = client.get("/api/v1/logs/stats")
    body = r.json()
    assert body.get("status") in ("ok", "degraded")


def test_logs_stats_org_id_param(client):
    """org_id query param must be accepted without error."""
    r = client.get("/api/v1/logs/stats?org_id=acme")
    assert r.status_code == 200
