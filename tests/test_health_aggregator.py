"""Tests for /api/v1/health/comprehensive aggregator endpoint."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    # Build a minimal app containing only the health router to avoid the
    # full create_app() startup cost (which exceeds the 10s timeout).
    from apps.api.health import router as health_router

    app = FastAPI()
    app.include_router(health_router)
    return TestClient(app)


def test_comprehensive_health_returns_200(client):
    resp = client.get("/api/v1/health/comprehensive")
    assert resp.status_code == 200


def test_comprehensive_health_has_status_field(client):
    resp = client.get("/api/v1/health/comprehensive")
    body = resp.json()
    assert "status" in body
    assert body["status"] in ("ok", "degraded")


def test_comprehensive_health_check_shapes_valid(client):
    resp = client.get("/api/v1/health/comprehensive")
    body = resp.json()
    assert "checks" in body
    assert isinstance(body["checks"], dict)
    # Each check must have a "status" key with a non-empty string value
    for name, check in body["checks"].items():
        assert "status" in check, f"check '{name}' missing 'status'"
        assert isinstance(check["status"], str), f"check '{name}' status must be str"
        assert check["status"], f"check '{name}' status must be non-empty"
    # elapsed_ms must be present and numeric
    assert "elapsed_ms" in body
    assert isinstance(body["elapsed_ms"], (int, float))
