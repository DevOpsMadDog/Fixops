"""HTTP-layer tests for security_baseline_router.

Covers the two core read/write endpoints:
  GET  /api/v1/security-baselines/          list_security_baselines
  POST /api/v1/security-baselines/baselines create_baseline

Auth: api_key_auth dependency overridden with a no-op so tests run without
a real API key.  Engine uses a tmp_path SQLite DB (real engine, no mocks).

Tests: 6
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from apps.api.security_baseline_router import router, _get_engine
from apps.api.auth_deps import api_key_auth
from core.security_baseline_engine import SecurityBaselineEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path):
    """Minimal FastAPI app with the security-baseline router and real engine."""
    app = FastAPI()

    # Override auth dependency — no-op, returns None
    app.dependency_overrides[api_key_auth] = lambda: None

    # Point the router's engine at a tmp DB so tests are fully isolated
    real_engine = SecurityBaselineEngine(db_path=str(tmp_path / "bl_router_test.db"))
    app.dependency_overrides[_get_engine] = lambda: real_engine

    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def client_with_baseline(client):
    """client + one pre-created baseline; returns (client, baseline_id)."""
    resp = client.post(
        "/api/v1/security-baselines/baselines",
        params={"org_id": "org1"},
        json={
            "baseline_name": "CIS Ubuntu 22.04",
            "target_type": "server",
            "framework": "CIS",
            "version": "1.0",
            "created_by": "testuser",
        },
    )
    assert resp.status_code == 201
    return client, resp.json()["id"]


# ---------------------------------------------------------------------------
# 1. GET / — list_security_baselines
# ---------------------------------------------------------------------------

class TestListSecurityBaselines:
    def test_empty_org_returns_empty_list(self, client):
        resp = client.get("/api/v1/security-baselines/", params={"org_id": "empty-org"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["baselines"] == []
        assert data["total"] == 0
        assert data["org_id"] == "empty-org"

    def test_lists_created_baseline(self, client_with_baseline):
        c, bl_id = client_with_baseline
        resp = c.get("/api/v1/security-baselines/", params={"org_id": "org1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["baselines"][0]["id"] == bl_id

    def test_org_isolation_separate_org_sees_zero(self, client_with_baseline):
        c, _ = client_with_baseline
        resp = c.get("/api/v1/security-baselines/", params={"org_id": "other-org"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 0


# ---------------------------------------------------------------------------
# 2. POST /baselines — create_baseline
# ---------------------------------------------------------------------------

class TestCreateBaseline:
    def test_create_returns_201_and_draft_status(self, client):
        resp = client.post(
            "/api/v1/security-baselines/baselines",
            params={"org_id": "org1"},
            json={
                "baseline_name": "PCI DSS v4",
                "target_type": "database",
                "framework": "PCI-DSS",
                "version": "4.0",
                "created_by": "admin",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "draft"
        assert data["control_count"] == 0
        assert data["framework"] == "PCI-DSS"

    def test_invalid_target_type_returns_422(self, client):
        resp = client.post(
            "/api/v1/security-baselines/baselines",
            params={"org_id": "org1"},
            json={
                "baseline_name": "Bad Baseline",
                "target_type": "spaceship",
                "framework": "CIS",
                "version": "1.0",
                "created_by": "admin",
            },
        )
        assert resp.status_code == 422

    def test_invalid_framework_returns_422(self, client):
        resp = client.post(
            "/api/v1/security-baselines/baselines",
            params={"org_id": "org1"},
            json={
                "baseline_name": "Unknown Framework",
                "target_type": "server",
                "framework": "UNKNOWN_FW",
                "version": "1.0",
                "created_by": "admin",
            },
        )
        assert resp.status_code == 422
