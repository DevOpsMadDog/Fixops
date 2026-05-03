"""HTTP-level tests for GET /api/v1/ide/ root endpoint.

Mounts only the ide_router (no full create_app() cost).
Verifies the real IDEIntegration engine is called — no mocks.
"""
from __future__ import annotations

import os

os.environ["FIXOPS_MODE"] = "enterprise"
os.environ["FIXOPS_API_TOKEN"] = "test-key"
os.environ["FIXOPS_JWT_SECRET"] = "test-secret-that-is-at-least-32chars!"
os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"
os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Mount only the ide_router to avoid full create_app() cost."""
    from apps.api.ide_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


AUTH = {"X-API-Key": "test-key"}


def test_ide_root_returns_200(client):
    """GET / returns HTTP 200."""
    r = client.get("/api/v1/ide/", headers=AUTH)
    assert r.status_code == 200, r.text


def test_ide_root_status_ok(client):
    """Response body contains status=ok."""
    data = client.get("/api/v1/ide/", headers=AUTH).json()
    assert data.get("status") == "ok"


def test_ide_root_has_pattern_count(client):
    """pattern_count is a non-negative integer from the real engine."""
    data = client.get("/api/v1/ide/", headers=AUTH).json()
    assert isinstance(data.get("pattern_count"), int)
    assert data["pattern_count"] >= 0


def test_ide_root_has_supported_languages(client):
    """supported_languages includes python."""
    data = client.get("/api/v1/ide/", headers=AUTH).json()
    langs = data.get("supported_languages", [])
    assert "python" in langs


def test_ide_root_endpoints_list_complete(client):
    """endpoints list contains at least 5 entries including scan/file."""
    data = client.get("/api/v1/ide/", headers=AUTH).json()
    endpoints = data.get("endpoints", [])
    assert len(endpoints) >= 5
    assert any("scan/file" in e for e in endpoints)


def test_ide_root_no_auth_returns_401_or_403(client):
    """Without API key the router rejects the request."""
    r = client.get("/api/v1/ide/")
    assert r.status_code in (401, 403)
