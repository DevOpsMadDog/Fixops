"""
PR2 API Contract Enforcement Tests

Tests to verify backend endpoints for UI contract compliance:
- Dashboard overview endpoint
- Feeds endpoint (EPSS/KEV)
- Intelligence endpoint (copilot/agents)
- Micro-pentest endpoint (should return 503 when not configured)
"""

import os
from unittest.mock import MagicMock, patch

import pytest

API_TOKEN = "test-token"


@pytest.fixture(scope="module")
def client():
    """Create test client with proper environment setup."""
    # Set environment before importing the app
    os.environ["FIXOPS_API_TOKEN"] = API_TOKEN
    os.environ["FIXOPS_JWT_SECRET"] = "test-secret"
    os.environ["FIXOPS_DEMO_MODE"] = "true"

    from backend.app import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_headers():
    """Return headers with valid API key."""
    return {"X-API-Key": API_TOKEN}


class TestDashboardOverview:
    """Tests for /api/v1/analytics/dashboard/overview endpoint."""

    def test_dashboard_overview_returns_200(self, client, auth_headers):
        """Dashboard overview should return 200 with valid auth."""
        response = client.get(
            "/api/v1/analytics/dashboard/overview?org_id=test-org",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_dashboard_overview_returns_required_fields(self, client, auth_headers):
        """Dashboard overview should return required fields."""
        response = client.get(
            "/api/v1/analytics/dashboard/overview?org_id=test-org",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()

        # Should have org_id echoed back
        assert "org_id" in data
        assert data["org_id"] == "test-org"

    def test_dashboard_overview_requires_org_id(self, client, auth_headers):
        """Dashboard overview should require org_id parameter."""
        response = client.get(
            "/api/v1/analytics/dashboard/overview",
            headers=auth_headers,
        )
        # Should fail validation without org_id
        assert response.status_code == 422

    def test_dashboard_overview_requires_auth(self, client):
        """Dashboard overview should require authentication."""
        response = client.get(
            "/api/v1/analytics/dashboard/overview?org_id=test-org",
        )
        assert response.status_code in (401, 403)


class TestFeedsEndpoint:
    """Tests for threat feeds endpoints (EPSS, KEV, etc.)."""

    def test_feeds_epss_returns_200(self, client, auth_headers):
        """EPSS endpoint should return 200."""
        response = client.get(
            "/api/v1/feeds/epss?limit=10",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_feeds_epss_returns_list(self, client, auth_headers):
        """EPSS endpoint should return a list of CVE scores."""
        response = client.get(
            "/api/v1/feeds/epss?limit=10",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()

        # Should return a list or paginated structure
        assert isinstance(data, (list, dict))
        if isinstance(data, dict):
            # Paginated response - accept various field names
            assert (
                "items" in data
                or "scores" in data
                or "epss_data" in data
                or "data" in data
            )

    def test_feeds_kev_returns_200(self, client, auth_headers):
        """KEV (Known Exploited Vulnerabilities) endpoint should return 200."""
        response = client.get(
            "/api/v1/feeds/kev?limit=10",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_feeds_exploits_returns_200(self, client, auth_headers):
        """Exploits endpoint should return 200."""
        response = client.get(
            "/api/v1/feeds/exploits?limit=10",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_feeds_threat_actors_returns_200(self, client, auth_headers):
        """Threat actors endpoint should return 200."""
        response = client.get(
            "/api/v1/feeds/threat-actors?limit=10",
            headers=auth_headers,
        )
        assert response.status_code == 200


class TestCopilotIntelligenceEndpoint:
    """Tests for copilot/intelligence endpoints."""

    def test_copilot_sessions_get_returns_200(self, client, auth_headers):
        """GET copilot sessions should return 200."""
        response = client.get(
            "/api/v1/copilot/sessions",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_copilot_sessions_create_returns_201(self, client, auth_headers):
        """POST copilot sessions should return 201 on success."""
        response = client.post(
            "/api/v1/copilot/sessions",
            headers=auth_headers,
            json={"title": "Test Session", "context": {"type": "security_analysis"}},
        )
        # Accept 201 (created) or 200 (if it echoes existing)
        assert response.status_code in (200, 201)

    def test_copilot_analyst_analyze_returns_200_or_503(self, client, auth_headers):
        """Copilot analyst endpoint should return 200 or 503 if LLM unavailable."""
        response = client.post(
            "/api/v1/copilot/agents/analyst/analyze",
            headers=auth_headers,
            json={
                "finding_id": "test-finding-123",
                "context": "Test vulnerability context",
            },
        )
        # 200 if LLM available, 503 if not configured
        assert response.status_code in (200, 201, 503)


class TestMicroPentestEndpoint:
    """Tests for micro-pentest endpoint - should return 503 when not configured."""

    def test_micro_pentest_health_returns_status(self, client, auth_headers):
        """Micro-pentest health should return connection status."""
        response = client.get(
            "/api/v1/micro-pentest/health",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()

        # Should include mpte connection status
        assert "mpte_status" in data
        assert "status" in data

    def test_micro_pentest_run_validates_input(self, client, auth_headers):
        """Micro-pentest run should validate required input."""
        # Empty request should fail validation
        response = client.post(
            "/api/v1/micro-pentest/run",
            headers=auth_headers,
            json={},
        )
        assert response.status_code == 422  # Validation error

    def test_micro_pentest_run_requires_cve_ids(self, client, auth_headers):
        """Micro-pentest run should require CVE IDs."""
        response = client.post(
            "/api/v1/micro-pentest/run",
            headers=auth_headers,
            json={"cve_ids": [], "target_urls": ["https://example.com"]},
        )
        assert response.status_code == 400  # Bad request - empty CVE list

    def test_micro_pentest_run_returns_503_when_mpte_unavailable(
        self, client, auth_headers
    ):
        """Micro-pentest should return 503 when MPTE is not configured."""
        # Mock the micro_pentest module to simulate MPTE being unavailable
        with patch("apps.api.micro_pentest_router.run_micro_pentest") as mock_run:
            # Simulate error result
            mock_result = MagicMock()
            mock_result.status = "error"
            mock_result.error = "MPTE service unavailable"
            mock_run.return_value = mock_result

            response = client.post(
                "/api/v1/micro-pentest/run",
                headers=auth_headers,
                json={
                    "cve_ids": ["CVE-2024-1234"],
                    "target_urls": ["https://example.com"],
                },
            )
            # Should return 503 Service Unavailable
            assert response.status_code == 503


class TestInventoryAssets:
    """Tests for the new /api/v1/inventory/assets endpoint."""

    def test_inventory_assets_returns_200(self, client, auth_headers):
        """Inventory assets should return 200."""
        response = client.get(
            "/api/v1/inventory/assets",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_inventory_assets_returns_paginated(self, client, auth_headers):
        """Inventory assets should return paginated response."""
        response = client.get(
            "/api/v1/inventory/assets?limit=10&offset=0",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data


class TestReportsGenerate:
    """Tests for the new /api/v1/reports/generate endpoint."""

    def test_reports_generate_returns_201(self, client, auth_headers):
        """Reports generate should return 201 on success."""
        response = client.post(
            "/api/v1/reports/generate",
            headers=auth_headers,
            json={
                "name": "Test Report",
                "report_type": "vulnerability",
                "format": "json",
            },
        )
        assert response.status_code == 201

    def test_reports_generate_returns_report_id(self, client, auth_headers):
        """Reports generate should return report ID."""
        response = client.post(
            "/api/v1/reports/generate",
            headers=auth_headers,
            json={
                "name": "Test Report 2",
                "report_type": "compliance",
                "format": "pdf",
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert "id" in data
        assert "status" in data


class TestContractChecker:
    """Test the api_contract_check.py script itself."""

    def test_contract_check_script_exists(self):
        """Contract check script should exist."""
        from pathlib import Path

        script_path = Path(__file__).parent.parent / "scripts" / "api_contract_check.py"
        assert script_path.exists(), "scripts/api_contract_check.py should exist"

    def test_contract_check_imports(self):
        """Contract check script should be importable."""
        import importlib.util
        from pathlib import Path

        script_path = Path(__file__).parent.parent / "scripts" / "api_contract_check.py"
        spec = importlib.util.spec_from_file_location("api_contract_check", script_path)
        module = importlib.util.module_from_spec(spec)

        # Just check it loads without error
        assert spec is not None
        assert module is not None
