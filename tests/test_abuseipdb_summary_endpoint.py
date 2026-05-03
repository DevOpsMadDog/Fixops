"""Tests for the AbuseIPDB GET / summary endpoint (empty-endpoints batch)."""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from fastapi import FastAPI
    from apps.api.abuseipdb_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None  # bypass auth
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helper — fake importer tuple
# ---------------------------------------------------------------------------

def _mock_importer(total_ips: int = 5000, by_source: Dict[str, Any] = None):
    """Return a (_run, _list, _check, get_store_stats) tuple for patching."""
    if by_source is None:
        by_source = {"et": 4000, "abuseipdb": 1000}
    stats = {"total_ips": total_ips, "by_source": by_source}

    get_store_stats = MagicMock(return_value=stats)
    run_import = MagicMock(return_value={"imported": total_ips})
    list_ips = MagicMock(return_value=[])
    check_ip = MagicMock(return_value=None)
    return run_import, list_ips, check_ip, get_store_stats


# ---------------------------------------------------------------------------
# Tests — GET /
# ---------------------------------------------------------------------------

class TestAbuseIPDBSummaryHealthy:
    def test_status_200(self, client):
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=_mock_importer(total_ips=5000),
        ):
            resp = client.get("/api/v1/abuseipdb/")
        assert resp.status_code == 200

    def test_healthy_status_when_ips_present(self, client):
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=_mock_importer(total_ips=5000),
        ):
            data = client.get("/api/v1/abuseipdb/").json()
        assert data["status"] == "healthy"

    def test_domain_field(self, client):
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=_mock_importer(total_ips=5000),
        ):
            data = client.get("/api/v1/abuseipdb/").json()
        assert data["domain"] == "abuseipdb"

    def test_stats_present(self, client):
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=_mock_importer(total_ips=5000),
        ):
            data = client.get("/api/v1/abuseipdb/").json()
        assert "stats" in data
        assert data["stats"]["total_ips"] == 5000


class TestAbuseIPDBSummaryEmpty:
    def test_empty_status_when_no_ips(self, client):
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=_mock_importer(total_ips=0),
        ):
            data = client.get("/api/v1/abuseipdb/").json()
        assert data["status"] == "empty"

    def test_hint_present_when_empty(self, client):
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=_mock_importer(total_ips=0),
        ):
            data = client.get("/api/v1/abuseipdb/").json()
        assert "hint" in data
        assert "import" in data["hint"].lower()

    def test_no_hint_when_healthy(self, client):
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=_mock_importer(total_ips=100),
        ):
            data = client.get("/api/v1/abuseipdb/").json()
        assert data.get("hint") is None


class TestAbuseIPDBSummaryError:
    def test_error_status_on_exception(self, client):
        def _raise():
            raise RuntimeError("db corrupted")

        broken_importer = (MagicMock(), MagicMock(), MagicMock(), _raise)
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=broken_importer,
        ):
            data = client.get("/api/v1/abuseipdb/").json()
        assert data["status"] == "error"
        assert "error" in data

    def test_error_contains_message(self, client):
        def _raise():
            raise RuntimeError("db corrupted")

        broken_importer = (MagicMock(), MagicMock(), MagicMock(), _raise)
        with patch(
            "apps.api.abuseipdb_router._get_importer",
            return_value=broken_importer,
        ):
            data = client.get("/api/v1/abuseipdb/").json()
        assert "db corrupted" in data["error"]
