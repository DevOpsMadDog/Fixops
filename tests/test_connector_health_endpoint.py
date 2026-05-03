"""Tests for GET /api/v1/connectors/{name}/health endpoint.

Covers:
- 200 healthy response with correct shape
- 200 unhealthy connector (healthy=False) still returns 200 (not an HTTP error)
- 404 when connector name not registered
- 502 when health_check() raises an unexpected exception
- name normalisation (uppercase in path → lowercase lookup)
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.timeout(10)

# ---------------------------------------------------------------------------
# App fixture — mount only the connectors router to keep tests isolated
# ---------------------------------------------------------------------------


@pytest.fixture()
def client():
    from fastapi import FastAPI
    from apps.api.connectors_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _health(healthy: bool, latency_ms: float = 45.0, message: str = "ok") -> MagicMock:
    """Return a mock ConnectorHealth whose to_dict() is realistic."""
    h = MagicMock()
    h.to_dict.return_value = {
        "healthy": healthy,
        "latency_ms": latency_ms,
        "message": message,
        "checked_at": "2026-05-03T00:00:00+00:00",
    }
    return h


def _make_uc(connector: MagicMock | None) -> MagicMock:
    uc = MagicMock()
    uc.get_connector.return_value = connector
    return uc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestConnectorHealthEndpoint:
    def test_healthy_connector_returns_200_with_shape(self, client):
        """Healthy connector → 200, correct JSON keys including 'name'."""
        conn = MagicMock()
        conn.health_check.return_value = _health(True, 32.1, "reachable")

        with patch("apps.api.connectors_router._get_universal", return_value=_make_uc(conn)):
            resp = client.get("/api/v1/connectors/my-jira/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["healthy"] is True
        assert body["name"] == "my-jira"
        assert "latency_ms" in body
        assert "checked_at" in body
        conn.health_check.assert_called_once()

    def test_unhealthy_connector_still_returns_200(self, client):
        """An unhealthy connector is not an HTTP error — 200 with healthy=False."""
        conn = MagicMock()
        conn.health_check.return_value = _health(False, 9999.0, "connection refused")

        with patch("apps.api.connectors_router._get_universal", return_value=_make_uc(conn)):
            resp = client.get("/api/v1/connectors/slack-prod/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["healthy"] is False
        assert body["name"] == "slack-prod"
        assert body["message"] == "connection refused"

    def test_missing_connector_returns_404(self, client):
        """Unknown connector name → 404."""
        with patch("apps.api.connectors_router._get_universal", return_value=_make_uc(None)):
            resp = client.get("/api/v1/connectors/does-not-exist/health")

        assert resp.status_code == 404
        assert "does-not-exist" in resp.json()["detail"]

    def test_health_check_exception_returns_502(self, client):
        """If health_check() raises, the endpoint returns 502 not 500."""
        conn = MagicMock()
        conn.health_check.side_effect = RuntimeError("network timeout")

        with patch("apps.api.connectors_router._get_universal", return_value=_make_uc(conn)):
            resp = client.get("/api/v1/connectors/github-main/health")

        assert resp.status_code == 502
        assert "github-main" in resp.json()["detail"]

    def test_name_is_normalised_to_lowercase(self, client):
        """Path segment 'GitHub-Main' must be looked up as 'github-main'."""
        conn = MagicMock()
        conn.health_check.return_value = _health(True)
        uc = _make_uc(conn)

        with patch("apps.api.connectors_router._get_universal", return_value=uc):
            resp = client.get("/api/v1/connectors/GitHub-Main/health")

        assert resp.status_code == 200
        # Verify the lookup used the lowercased name
        uc.get_connector.assert_called_once_with("github-main")
        assert resp.json()["name"] == "github-main"
