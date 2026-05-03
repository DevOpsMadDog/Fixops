"""Tests for access_control_router GET / status endpoint."""
from __future__ import annotations

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from fastapi.testclient import TestClient
from fastapi import FastAPI
from unittest.mock import patch, MagicMock

from apps.api.access_control_router import router


# ---------------------------------------------------------------------------
# App fixture — bypass api_key_auth for unit tests
# ---------------------------------------------------------------------------

def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)

    # Override auth dependency to always pass
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: "test-key"
    return app


@pytest.fixture()
def client():
    return TestClient(_make_app())


@pytest.fixture()
def mock_engine():
    """Return a mock engine with realistic stat values."""
    eng = MagicMock()
    eng.get_access_stats.return_value = {
        "total_policies": 12,
        "active_grants": 5,
        "revoked_grants": 2,
        "expired_grants": 1,
        "by_resource_type": {"api": 6, "database": 6},
        "by_effect": {"allow": 10, "deny": 2},
        "total_grants": 8,
    }
    return eng


# ---------------------------------------------------------------------------
# GET / tests
# ---------------------------------------------------------------------------

class TestGetAccessControlStatus:
    def test_returns_200(self, client, mock_engine):
        with patch("apps.api.access_control_router._get_engine", return_value=mock_engine):
            r = client.get("/api/v1/access-control/")
        assert r.status_code == 200

    def test_status_is_healthy(self, client, mock_engine):
        with patch("apps.api.access_control_router._get_engine", return_value=mock_engine):
            body = client.get("/api/v1/access-control/").json()
        assert body["status"] == "healthy"

    def test_engine_field(self, client, mock_engine):
        with patch("apps.api.access_control_router._get_engine", return_value=mock_engine):
            body = client.get("/api/v1/access-control/").json()
        assert body["engine"] == "access-control"

    def test_counts_come_from_engine(self, client, mock_engine):
        with patch("apps.api.access_control_router._get_engine", return_value=mock_engine):
            body = client.get("/api/v1/access-control/").json()
        assert body["total_policies"] == 12
        assert body["active_grants"] == 5
        assert body["revoked_grants"] == 2
        assert body["expired_grants"] == 1

    def test_org_id_param_forwarded(self, client, mock_engine):
        with patch("apps.api.access_control_router._get_engine", return_value=mock_engine):
            body = client.get("/api/v1/access-control/?org_id=acme").json()
        mock_engine.get_access_stats.assert_called_once_with("acme")
        assert body["org_id"] == "acme"

    def test_default_org_id(self, client, mock_engine):
        with patch("apps.api.access_control_router._get_engine", return_value=mock_engine):
            body = client.get("/api/v1/access-control/").json()
        assert body["org_id"] == "default"

    def test_engine_error_propagates_500(self, client):
        bad_engine = MagicMock()
        bad_engine.get_access_stats.side_effect = RuntimeError("db gone")
        with patch("apps.api.access_control_router._get_engine", return_value=bad_engine):
            r = client.get("/api/v1/access-control/")
        assert r.status_code == 500
