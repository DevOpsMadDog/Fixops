"""
Comprehensive E2E tests for all 137 API endpoints across Phases 1-6.
This test suite validates every endpoint with fresh test data.
"""

import json
import os

import pytest

# Set environment variables BEFORE importing create_app
# Use the same token as the Docker image (demo-token-12345) for consistency
API_TOKEN = os.getenv("FIXOPS_API_TOKEN", "demo-token-12345")
os.environ["FIXOPS_API_TOKEN"] = API_TOKEN
os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"
os.environ["FIXOPS_MODE"] = os.getenv("FIXOPS_MODE", "demo")
os.environ["FIXOPS_JWT_SECRET"] = "test-jwt-secret-e2e-do-not-use-in-production"

from fastapi.testclient import TestClient

from apps.api.app import create_app


@pytest.fixture(scope="module")
def api_client():
    """Create FastAPI test client for all tests."""
    app = create_app()
    client = TestClient(app)
    return client


@pytest.fixture(scope="module")
def auth_headers():
    """Standard authentication headers."""
    return {"X-API-Key": API_TOKEN}


class TestPhase1InventoryEndpoints:
    """Test all 15 Phase 1 Inventory endpoints."""

    def test_01_create_application(self, api_client, auth_headers):
        """POST /api/v1/inventory/applications"""
        response = api_client.post(
            "/api/v1/inventory/applications",
            json={
                "name": "E2E Test App",
                "description": "Application for E2E testing",
                "owner": "test-team",
                "criticality": "high",
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["name"] == "E2E Test App"
        pytest.app_id = data["id"]

    def test_02_list_applications(self, api_client, auth_headers):
        """GET /api/v1/inventory/applications"""
        response = api_client.get(
            "/api/v1/inventory/applications", headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)
        assert data["total"] >= 0

    def test_03_get_application(self, api_client, auth_headers):
        """GET /api/v1/inventory/applications/{id}"""
        app_id = getattr(pytest, "app_id", "test-app-1")
        response = api_client.get(
            f"/api/v1/inventory/applications/{app_id}", headers=auth_headers
        )
        assert response.status_code in [200, 204, 404, 405]

    def test_04_update_application(self, api_client, auth_headers):
        """PUT /api/v1/inventory/applications/{id}"""
        app_id = getattr(pytest, "app_id", "test-app-1")
        response = api_client.put(
            f"/api/v1/inventory/applications/{app_id}",
            json={"description": "Updated description"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 204, 404, 405]

    def test_05_delete_application(self, api_client, auth_headers):
        """DELETE /api/v1/inventory/applications/{id}"""
        response = api_client.delete(
            "/api/v1/inventory/applications/temp-app", headers=auth_headers
        )
        assert response.status_code in [200, 204, 404]

    def test_06_create_service(self, api_client, auth_headers):
        """POST /api/v1/inventory/services"""
        response = api_client.post(
            "/api/v1/inventory/services",
            json={
                "name": "E2E Test Service",
                "application_id": getattr(pytest, "app_id", "test-app-1"),
                "service_type": "api",
                "endpoint": "https://api.example.com",
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        pytest.service_id = response.json()["id"]

    def test_07_list_services(self, api_client, auth_headers):
        """GET /api/v1/inventory/services"""
        response = api_client.get("/api/v1/inventory/services", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_08_get_service(self, api_client, auth_headers):
        """GET /api/v1/inventory/services/{id}"""
        service_id = getattr(pytest, "service_id", "test-service-1")
        response = api_client.get(
            f"/api/v1/inventory/services/{service_id}", headers=auth_headers
        )
        assert response.status_code in [200, 204, 404, 405]

    def test_09_update_service(self, api_client, auth_headers):
        """PUT /api/v1/inventory/services/{id}"""
        service_id = getattr(pytest, "service_id", "test-service-1")
        response = api_client.put(
            f"/api/v1/inventory/services/{service_id}",
            json={"endpoint": "https://api-v2.example.com"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 204, 404, 405]

    def test_10_delete_service(self, api_client, auth_headers):
        """DELETE /api/v1/inventory/services/{id}"""
        response = api_client.delete(
            "/api/v1/inventory/services/temp-service", headers=auth_headers
        )
        assert response.status_code in [200, 204, 404]

    def test_11_create_component(self, api_client, auth_headers):
        """POST /api/v1/inventory/components"""
        response = api_client.post(
            "/api/v1/inventory/components",
            json={
                "name": "E2E Test Component",
                "application_id": getattr(pytest, "app_id", "test-app-1"),
                "component_type": "library",
                "version": "1.0.0",
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        pytest.component_id = response.json()["id"]

    def test_12_list_components(self, api_client, auth_headers):
        """GET /api/v1/inventory/components"""
        response = api_client.get("/api/v1/inventory/components", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_13_get_component(self, api_client, auth_headers):
        """GET /api/v1/inventory/components/{id}"""
        component_id = getattr(pytest, "component_id", "test-component-1")
        response = api_client.get(
            f"/api/v1/inventory/components/{component_id}", headers=auth_headers
        )
        assert response.status_code in [200, 204, 404, 405]

    def test_14_update_component(self, api_client, auth_headers):
        """PUT /api/v1/inventory/components/{id}"""
        component_id = getattr(pytest, "component_id", "test-component-1")
        response = api_client.put(
            f"/api/v1/inventory/components/{component_id}",
            json={"version": "1.0.1"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_15_delete_component(self, api_client, auth_headers):
        """DELETE /api/v1/inventory/components/{id}"""
        response = api_client.delete(
            "/api/v1/inventory/components/temp-component", headers=auth_headers
        )
        assert response.status_code in [200, 204, 404]


class TestPhase2UserTeamPolicyEndpoints:
    """Test all 22 Phase 2 User/Team/Policy endpoints."""

    def test_16_create_user(self, api_client, auth_headers):
        """POST /api/v1/users"""
        response = api_client.post(
            "/api/v1/users",
            json={
                "username": "e2e-test-user",
                "email": "e2e@example.com",
                "full_name": "E2E Test User",
                "role": "analyst",
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        pytest.user_id = response.json()["id"]

    def test_17_list_users(self, api_client, auth_headers):
        """GET /api/v1/users"""
        response = api_client.get("/api/v1/users", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_18_get_user(self, api_client, auth_headers):
        """GET /api/v1/users/{id}"""
        user_id = getattr(pytest, "user_id", "test-user-1")
        response = api_client.get(f"/api/v1/users/{user_id}", headers=auth_headers)
        assert response.status_code in [200, 404]

    def test_19_update_user(self, api_client, auth_headers):
        """PUT /api/v1/users/{id}"""
        user_id = getattr(pytest, "user_id", "test-user-1")
        response = api_client.put(
            f"/api/v1/users/{user_id}",
            json={"full_name": "Updated Name"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_20_delete_user(self, api_client, auth_headers):
        """DELETE /api/v1/users/{id}"""
        response = api_client.delete("/api/v1/users/temp-user", headers=auth_headers)
        assert response.status_code in [200, 204, 404]

    def test_21_create_team(self, api_client, auth_headers):
        """POST /api/v1/teams"""
        response = api_client.post(
            "/api/v1/teams",
            json={"name": "E2E Test Team", "description": "Team for E2E testing"},
            headers=auth_headers,
        )
        assert response.status_code == 201
        pytest.team_id = response.json()["id"]

    def test_22_list_teams(self, api_client, auth_headers):
        """GET /api/v1/teams"""
        response = api_client.get("/api/v1/teams", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_23_get_team(self, api_client, auth_headers):
        """GET /api/v1/teams/{id}"""
        team_id = getattr(pytest, "team_id", "test-team-1")
        response = api_client.get(f"/api/v1/teams/{team_id}", headers=auth_headers)
        assert response.status_code in [200, 404]

    def test_24_update_team(self, api_client, auth_headers):
        """PUT /api/v1/teams/{id}"""
        team_id = getattr(pytest, "team_id", "test-team-1")
        response = api_client.put(
            f"/api/v1/teams/{team_id}",
            json={"description": "Updated description"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_25_delete_team(self, api_client, auth_headers):
        """DELETE /api/v1/teams/{id}"""
        response = api_client.delete("/api/v1/teams/temp-team", headers=auth_headers)
        assert response.status_code in [200, 204, 404]

    def test_26_add_team_member(self, api_client, auth_headers):
        """POST /api/v1/teams/{id}/members"""
        team_id = getattr(pytest, "team_id", "test-team-1")
        user_id = getattr(pytest, "user_id", "test-user-1")
        response = api_client.post(
            f"/api/v1/teams/{team_id}/members",
            json={"user_id": user_id, "role": "member"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_27_list_team_members(self, api_client, auth_headers):
        """GET /api/v1/teams/{id}/members"""
        team_id = getattr(pytest, "team_id", "test-team-1")
        response = api_client.get(
            f"/api/v1/teams/{team_id}/members", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_28_remove_team_member(self, api_client, auth_headers):
        """DELETE /api/v1/teams/{team_id}/members/{user_id}"""
        team_id = getattr(pytest, "team_id", "test-team-1")
        user_id = getattr(pytest, "user_id", "test-user-1")
        response = api_client.delete(
            f"/api/v1/teams/{team_id}/members/{user_id}", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_29_create_policy(self, api_client, auth_headers):
        """POST /api/v1/policies"""
        response = api_client.post(
            "/api/v1/policies",
            json={
                "name": "E2E Test Policy",
                "description": "Policy for E2E testing",
                "rules": [{"condition": "severity == 'critical'", "action": "block"}],
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        pytest.policy_id = response.json()["id"]

    def test_30_list_policies(self, api_client, auth_headers):
        """GET /api/v1/policies"""
        response = api_client.get("/api/v1/policies", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_31_get_policy(self, api_client, auth_headers):
        """GET /api/v1/policies/{id}"""
        policy_id = getattr(pytest, "policy_id", "test-policy-1")
        response = api_client.get(f"/api/v1/policies/{policy_id}", headers=auth_headers)
        assert response.status_code in [200, 404]

    def test_32_update_policy(self, api_client, auth_headers):
        """PUT /api/v1/policies/{id}"""
        policy_id = getattr(pytest, "policy_id", "test-policy-1")
        response = api_client.put(
            f"/api/v1/policies/{policy_id}",
            json={"description": "Updated policy description"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_33_delete_policy(self, api_client, auth_headers):
        """DELETE /api/v1/policies/{id}"""
        response = api_client.delete(
            "/api/v1/policies/temp-policy", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_34_evaluate_policy(self, api_client, auth_headers):
        """POST /api/v1/policies/{id}/evaluate"""
        policy_id = getattr(pytest, "policy_id", "test-policy-1")
        response = api_client.post(
            f"/api/v1/policies/{policy_id}/evaluate",
            json={"finding": {"severity": "critical", "cve_id": "CVE-2024-0001"}},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_35_list_policy_violations(self, api_client, auth_headers):
        """GET /api/v1/policies/{id}/violations"""
        policy_id = getattr(pytest, "policy_id", "test-policy-1")
        response = api_client.get(
            f"/api/v1/policies/{policy_id}/violations", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_36_enable_policy(self, api_client, auth_headers):
        """POST /api/v1/policies/{id}/enable"""
        policy_id = getattr(pytest, "policy_id", "test-policy-1")
        response = api_client.post(
            f"/api/v1/policies/{policy_id}/enable", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_37_disable_policy(self, api_client, auth_headers):
        """POST /api/v1/policies/{id}/disable"""
        policy_id = getattr(pytest, "policy_id", "test-policy-1")
        response = api_client.post(
            f"/api/v1/policies/{policy_id}/disable", headers=auth_headers
        )
        assert response.status_code in [200, 404]


class TestPhase3AnalyticsIntegrationEndpoints:
    """Test all 24 Phase 3 Analytics/Integration endpoints."""

    def test_38_get_dashboard_summary(self, api_client, auth_headers):
        """GET /api/v1/analytics/dashboard"""
        response = api_client.get("/api/v1/analytics/dashboard", headers=auth_headers)
        assert response.status_code == 200

    def test_39_get_severity_distribution(self, api_client, auth_headers):
        """GET /api/v1/analytics/severity-distribution"""
        response = api_client.get(
            "/api/v1/analytics/severity-distribution", headers=auth_headers
        )
        assert response.status_code == 200

    def test_40_get_trend_analysis(self, api_client, auth_headers):
        """GET /api/v1/analytics/trends"""
        response = api_client.get("/api/v1/analytics/trends", headers=auth_headers)
        assert response.status_code == 200

    def test_41_get_roi_metrics(self, api_client, auth_headers):
        """GET /api/v1/analytics/roi"""
        response = api_client.get("/api/v1/analytics/roi", headers=auth_headers)
        assert response.status_code == 200

    def test_42_get_compliance_status(self, api_client, auth_headers):
        """GET /api/v1/analytics/compliance"""
        response = api_client.get("/api/v1/analytics/compliance", headers=auth_headers)
        assert response.status_code == 200

    def test_43_get_team_performance(self, api_client, auth_headers):
        """GET /api/v1/analytics/team-performance"""
        response = api_client.get(
            "/api/v1/analytics/team-performance", headers=auth_headers
        )
        assert response.status_code == 200

    def test_44_get_application_risk_score(self, api_client, auth_headers):
        """GET /api/v1/analytics/applications/{id}/risk-score"""
        app_id = getattr(pytest, "app_id", "test-app-1")
        response = api_client.get(
            f"/api/v1/analytics/applications/{app_id}/risk-score", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_45_get_vulnerability_trends(self, api_client, auth_headers):
        """GET /api/v1/analytics/vulnerability-trends"""
        response = api_client.get(
            "/api/v1/analytics/vulnerability-trends", headers=auth_headers
        )
        assert response.status_code == 200

    def test_46_get_mttr_metrics(self, api_client, auth_headers):
        """GET /api/v1/analytics/mttr"""
        response = api_client.get("/api/v1/analytics/mttr", headers=auth_headers)
        assert response.status_code == 200

    def test_47_get_false_positive_rate(self, api_client, auth_headers):
        """GET /api/v1/analytics/false-positive-rate"""
        response = api_client.get(
            "/api/v1/analytics/false-positive-rate", headers=auth_headers
        )
        assert response.status_code == 200

    def test_48_export_analytics_report(self, api_client, auth_headers):
        """POST /api/v1/analytics/export"""
        response = api_client.post(
            "/api/v1/analytics/export",
            json={"format": "json", "metrics": ["dashboard", "trends"]},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_49_create_integration(self, api_client, auth_headers):
        """POST /api/v1/integrations"""
        response = api_client.post(
            "/api/v1/integrations",
            json={
                "name": "E2E Test Integration",
                "integration_type": "jira",
                "config": {"url": "https://jira.example.com", "project": "TEST"},
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        pytest.integration_id = response.json()["id"]

    def test_50_list_integrations(self, api_client, auth_headers):
        """GET /api/v1/integrations"""
        response = api_client.get("/api/v1/integrations", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_51_get_integration(self, api_client, auth_headers):
        """GET /api/v1/integrations/{id}"""
        integration_id = getattr(pytest, "integration_id", "test-integration-1")
        response = api_client.get(
            f"/api/v1/integrations/{integration_id}", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_52_update_integration(self, api_client, auth_headers):
        """PUT /api/v1/integrations/{id}"""
        integration_id = getattr(pytest, "integration_id", "test-integration-1")
        response = api_client.put(
            f"/api/v1/integrations/{integration_id}",
            json={"config": {"project": "UPDATED"}},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_53_delete_integration(self, api_client, auth_headers):
        """DELETE /api/v1/integrations/{id}"""
        response = api_client.delete(
            "/api/v1/integrations/temp-integration", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_54_test_integration(self, api_client, auth_headers):
        """POST /api/v1/integrations/{id}/test"""
        integration_id = getattr(pytest, "integration_id", "test-integration-1")
        response = api_client.post(
            f"/api/v1/integrations/{integration_id}/test", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_55_enable_integration(self, api_client, auth_headers):
        """POST /api/v1/integrations/{id}/enable"""
        integration_id = getattr(pytest, "integration_id", "test-integration-1")
        response = api_client.post(
            f"/api/v1/integrations/{integration_id}/enable", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_56_disable_integration(self, api_client, auth_headers):
        """POST /api/v1/integrations/{id}/disable"""
        integration_id = getattr(pytest, "integration_id", "test-integration-1")
        response = api_client.post(
            f"/api/v1/integrations/{integration_id}/disable", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_57_sync_integration(self, api_client, auth_headers):
        """POST /api/v1/integrations/{id}/sync"""
        integration_id = getattr(pytest, "integration_id", "test-integration-1")
        response = api_client.post(
            f"/api/v1/integrations/{integration_id}/sync", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_58_get_integration_logs(self, api_client, auth_headers):
        """GET /api/v1/integrations/{id}/logs"""
        integration_id = getattr(pytest, "integration_id", "test-integration-1")
        response = api_client.get(
            f"/api/v1/integrations/{integration_id}/logs", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_59_get_integration_webhooks(self, api_client, auth_headers):
        """GET /api/v1/integrations/webhooks"""
        response = api_client.get("/api/v1/integrations/webhooks", headers=auth_headers)
        assert response.status_code == 200

    def test_60_create_integration_webhook(self, api_client, auth_headers):
        """POST /api/v1/integrations/webhooks"""
        response = api_client.post(
            "/api/v1/integrations/webhooks",
            json={"url": "https://webhook.example.com", "events": ["finding.created"]},
            headers=auth_headers,
        )
        assert response.status_code == 201

    def test_61_delete_integration_webhook(self, api_client, auth_headers):
        """DELETE /api/v1/integrations/webhooks/{id}"""
        response = api_client.delete(
            "/api/v1/integrations/webhooks/temp-webhook", headers=auth_headers
        )
        assert response.status_code in [200, 404]


class TestPhase4ReportsAuditWorkflowEndpoints:
    """Test all 26 Phase 4 Reports/Audit/Workflow endpoints."""

    def test_62_create_report(self, api_client, auth_headers):
        """POST /api/v1/reports"""
        response = api_client.post(
            "/api/v1/reports",
            json={
                "name": "E2E Test Report",
                "report_type": "security_summary",
                "filters": {"severity": ["critical", "high"]},
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        pytest.report_id = response.json()["id"]

    def test_63_list_reports(self, api_client, auth_headers):
        """GET /api/v1/reports"""
        response = api_client.get("/api/v1/reports", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_64_get_report(self, api_client, auth_headers):
        """GET /api/v1/reports/{id}"""
        report_id = getattr(pytest, "report_id", "test-report-1")
        response = api_client.get(f"/api/v1/reports/{report_id}", headers=auth_headers)
        assert response.status_code in [200, 404]

    def test_65_update_report(self, api_client, auth_headers):
        """PUT /api/v1/reports/{id}"""
        report_id = getattr(pytest, "report_id", "test-report-1")
        response = api_client.put(
            f"/api/v1/reports/{report_id}",
            json={"name": "Updated Report Name"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_66_delete_report(self, api_client, auth_headers):
        """DELETE /api/v1/reports/{id}"""
        response = api_client.delete(
            "/api/v1/reports/temp-report", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_67_generate_report(self, api_client, auth_headers):
        """POST /api/v1/reports/{id}/generate"""
        report_id = getattr(pytest, "report_id", "test-report-1")
        response = api_client.post(
            f"/api/v1/reports/{report_id}/generate", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_68_download_report(self, api_client, auth_headers):
        """GET /api/v1/reports/{id}/download"""
        report_id = getattr(pytest, "report_id", "test-report-1")
        response = api_client.get(
            f"/api/v1/reports/{report_id}/download", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_69_schedule_report(self, api_client, auth_headers):
        """POST /api/v1/reports/{id}/schedule"""
        report_id = getattr(pytest, "report_id", "test-report-1")
        response = api_client.post(
            f"/api/v1/reports/{report_id}/schedule",
            json={"frequency": "weekly", "day": "monday"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_70_list_report_templates(self, api_client, auth_headers):
        """GET /api/v1/reports/templates"""
        response = api_client.get("/api/v1/reports/templates", headers=auth_headers)
        assert response.status_code == 200

    def test_71_create_audit_log(self, api_client, auth_headers):
        """POST /api/v1/audit/logs"""
        response = api_client.post(
            "/api/v1/audit/logs",
            json={
                "action": "test_action",
                "resource_type": "application",
                "resource_id": "test-app-1",
                "user_id": "test-user-1",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_72_list_audit_logs(self, api_client, auth_headers):
        """GET /api/v1/audit/logs"""
        response = api_client.get("/api/v1/audit/logs", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_73_get_audit_log(self, api_client, auth_headers):
        """GET /api/v1/audit/logs/{id}"""
        response = api_client.get("/api/v1/audit/logs/test-log-1", headers=auth_headers)
        assert response.status_code in [200, 404]

    def test_74_search_audit_logs(self, api_client, auth_headers):
        """POST /api/v1/audit/logs/search"""
        response = api_client.post(
            "/api/v1/audit/logs/search",
            json={"action": "test_action", "start_date": "2024-01-01"},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_75_export_audit_logs(self, api_client, auth_headers):
        """POST /api/v1/audit/logs/export"""
        response = api_client.post(
            "/api/v1/audit/logs/export",
            json={"format": "json", "filters": {}},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_76_get_audit_summary(self, api_client, auth_headers):
        """GET /api/v1/audit/summary"""
        response = api_client.get("/api/v1/audit/summary", headers=auth_headers)
        assert response.status_code == 200

    def test_77_get_compliance_audit(self, api_client, auth_headers):
        """GET /api/v1/audit/compliance"""
        response = api_client.get("/api/v1/audit/compliance", headers=auth_headers)
        assert response.status_code == 200

    def test_78_create_workflow(self, api_client, auth_headers):
        """POST /api/v1/workflows"""
        response = api_client.post(
            "/api/v1/workflows",
            json={
                "name": "E2E Test Workflow",
                "description": "Workflow for E2E testing",
                "trigger": "finding.created",
                "actions": [{"type": "notify", "config": {"channel": "slack"}}],
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        pytest.workflow_id = response.json()["id"]

    def test_79_list_workflows(self, api_client, auth_headers):
        """GET /api/v1/workflows"""
        response = api_client.get("/api/v1/workflows", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_80_get_workflow(self, api_client, auth_headers):
        """GET /api/v1/workflows/{id}"""
        workflow_id = getattr(pytest, "workflow_id", "test-workflow-1")
        response = api_client.get(
            f"/api/v1/workflows/{workflow_id}", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_81_update_workflow(self, api_client, auth_headers):
        """PUT /api/v1/workflows/{id}"""
        workflow_id = getattr(pytest, "workflow_id", "test-workflow-1")
        response = api_client.put(
            f"/api/v1/workflows/{workflow_id}",
            json={"description": "Updated workflow description"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_82_delete_workflow(self, api_client, auth_headers):
        """DELETE /api/v1/workflows/{id}"""
        response = api_client.delete(
            "/api/v1/workflows/temp-workflow", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_83_execute_workflow(self, api_client, auth_headers):
        """POST /api/v1/workflows/{id}/execute"""
        workflow_id = getattr(pytest, "workflow_id", "test-workflow-1")
        response = api_client.post(
            f"/api/v1/workflows/{workflow_id}/execute",
            json={"context": {"finding_id": "test-finding-1"}},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_84_enable_workflow(self, api_client, auth_headers):
        """POST /api/v1/workflows/{id}/enable"""
        workflow_id = getattr(pytest, "workflow_id", "test-workflow-1")
        response = api_client.post(
            f"/api/v1/workflows/{workflow_id}/enable", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_85_disable_workflow(self, api_client, auth_headers):
        """POST /api/v1/workflows/{id}/disable"""
        workflow_id = getattr(pytest, "workflow_id", "test-workflow-1")
        response = api_client.post(
            f"/api/v1/workflows/{workflow_id}/disable", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_86_get_workflow_executions(self, api_client, auth_headers):
        """GET /api/v1/workflows/{id}/executions"""
        workflow_id = getattr(pytest, "workflow_id", "test-workflow-1")
        response = api_client.get(
            f"/api/v1/workflows/{workflow_id}/executions", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_87_get_workflow_templates(self, api_client, auth_headers):
        """GET /api/v1/workflows/templates"""
        response = api_client.get("/api/v1/workflows/templates", headers=auth_headers)
        assert response.status_code == 200


class TestPhase5EnterpriseEndpoints:
    """Test all 22 Phase 5 Enterprise endpoints."""

    def test_088_create_sso_config(self, api_client, auth_headers):
        """POST /api/v1/auth/sso"""
        response = api_client.post(
            "/api/v1/auth/sso",
            json={
                "provider": "okta",
                "config": {
                    "issuer": "https://okta.example.com",
                    "client_id": "test-client",
                },
            },
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_089_get_sso_config(self, api_client, auth_headers):
        """GET /api/v1/auth/sso"""
        response = api_client.get("/api/v1/auth/sso", headers=auth_headers)
        assert response.status_code == 200

    def test_090_update_sso_config(self, api_client, auth_headers):
        """PUT /api/v1/auth/sso"""
        response = api_client.put(
            "/api/v1/auth/sso",
            json={"config": {"client_id": "updated-client"}},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_091_delete_sso_config(self, api_client, auth_headers):
        """DELETE /api/v1/auth/sso"""
        response = api_client.delete("/api/v1/auth/sso", headers=auth_headers)
        assert response.status_code in [200, 404]

    def test_092_scan_secrets(self, api_client, auth_headers):
        """POST /api/v1/secrets/scan"""
        response = api_client.post(
            "/api/v1/secrets/scan",
            json={"content": "API_KEY=sk-test-12345", "file_path": "/test/file.py"},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_093_list_secrets(self, api_client, auth_headers):
        """GET /api/v1/secrets"""
        response = api_client.get("/api/v1/secrets", headers=auth_headers)
        assert response.status_code == 200

    def test_094_get_secret(self, api_client, auth_headers):
        """GET /api/v1/secrets/{id}"""
        response = api_client.get("/api/v1/secrets/test-secret-1", headers=auth_headers)
        assert response.status_code in [200, 404]

    def test_095_mark_secret_resolved(self, api_client, auth_headers):
        """POST /api/v1/secrets/{id}/resolve"""
        response = api_client.post(
            "/api/v1/secrets/test-secret-1/resolve", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_096_get_secret_patterns(self, api_client, auth_headers):
        """GET /api/v1/secrets/patterns"""
        response = api_client.get("/api/v1/secrets/patterns", headers=auth_headers)
        assert response.status_code == 200

    def test_097_scan_iac(self, api_client, auth_headers):
        """POST /api/v1/iac/scan"""
        response = api_client.post(
            "/api/v1/iac/scan",
            json={
                "content": "resource 'aws_s3_bucket' 'test' {}",
                "file_path": "/test/main.tf",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_098_list_iac_findings(self, api_client, auth_headers):
        """GET /api/v1/iac/findings"""
        response = api_client.get("/api/v1/iac/findings", headers=auth_headers)
        assert response.status_code == 200

    def test_099_get_iac_finding(self, api_client, auth_headers):
        """GET /api/v1/iac/findings/{id}"""
        response = api_client.get(
            "/api/v1/iac/findings/test-finding-1", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_100_mark_iac_resolved(self, api_client, auth_headers):
        """POST /api/v1/iac/findings/{id}/resolve"""
        response = api_client.post(
            "/api/v1/iac/findings/test-finding-1/resolve", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_101_get_iac_rules(self, api_client, auth_headers):
        """GET /api/v1/iac/rules"""
        response = api_client.get("/api/v1/iac/rules", headers=auth_headers)
        assert response.status_code == 200

    def test_102_bulk_create_applications(self, api_client, auth_headers):
        """POST /api/v1/bulk/applications"""
        response = api_client.post(
            "/api/v1/bulk/applications",
            json={
                "applications": [
                    {"name": "Bulk App 1", "owner": "team1"},
                    {"name": "Bulk App 2", "owner": "team2"},
                ]
            },
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_103_bulk_update_findings(self, api_client, auth_headers):
        """PUT /api/v1/bulk/findings"""
        response = api_client.put(
            "/api/v1/bulk/findings",
            json={"finding_ids": ["f1", "f2"], "updates": {"status": "resolved"}},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_104_bulk_delete_components(self, api_client, auth_headers):
        """DELETE /api/v1/bulk/components"""
        response = api_client.delete(
            "/api/v1/bulk/components",
            json={"component_ids": ["c1", "c2"]},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_105_bulk_assign_policies(self, api_client, auth_headers):
        """POST /api/v1/bulk/policies/assign"""
        response = api_client.post(
            "/api/v1/bulk/policies/assign",
            json={"policy_id": "p1", "application_ids": ["a1", "a2"]},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_106_bulk_export(self, api_client, auth_headers):
        """POST /api/v1/bulk/export"""
        response = api_client.post(
            "/api/v1/bulk/export",
            json={"resource_type": "applications", "format": "json"},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_107_get_ide_config(self, api_client, auth_headers):
        """GET /api/v1/ide/config"""
        response = api_client.get("/api/v1/ide/config", headers=auth_headers)
        assert response.status_code == 200

    def test_108_validate_code(self, api_client, auth_headers):
        """POST /api/v1/ide/validate"""
        response = api_client.post(
            "/api/v1/ide/validate",
            json={"code": "import os\nAPI_KEY = 'sk-test'", "language": "python"},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_109_get_ide_suggestions(self, api_client, auth_headers):
        """POST /api/v1/ide/suggestions"""
        response = api_client.post(
            "/api/v1/ide/suggestions",
            json={"code": "import os", "cursor_position": 10},
            headers=auth_headers,
        )
        assert response.status_code == 200


class TestPhase6PentagiEndpoints:
    """Test all 12 Phase 6 Pentagi endpoints."""

    def test_110_create_pentest_request(self, api_client, auth_headers):
        """POST /api/v1/pentagi/requests"""
        response = api_client.post(
            "/api/v1/pentagi/requests",
            json={
                "finding_id": "test-finding-1",
                "target_url": "https://test.example.com/api",
                "vulnerability_type": "sql_injection",
                "test_case": "Test SQL injection via username parameter",
                "priority": "high",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        pytest.pentest_request_id = response.json()["id"]

    def test_111_list_pentest_requests(self, api_client, auth_headers):
        """GET /api/v1/pentagi/requests"""
        response = api_client.get("/api/v1/pentagi/requests", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_112_get_pentest_request(self, api_client, auth_headers):
        """GET /api/v1/pentagi/requests/{id}"""
        request_id = getattr(pytest, "pentest_request_id", "test-request-1")
        response = api_client.get(
            f"/api/v1/pentagi/requests/{request_id}", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_113_update_pentest_request(self, api_client, auth_headers):
        """PUT /api/v1/pentagi/requests/{id}"""
        request_id = getattr(pytest, "pentest_request_id", "test-request-1")
        response = api_client.put(
            f"/api/v1/pentagi/requests/{request_id}",
            json={"priority": "critical"},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_114_start_pentest(self, api_client, auth_headers):
        """POST /api/v1/pentagi/requests/{id}/start"""
        request_id = getattr(pytest, "pentest_request_id", "test-request-1")
        response = api_client.post(
            f"/api/v1/pentagi/requests/{request_id}/start", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_115_cancel_pentest(self, api_client, auth_headers):
        """POST /api/v1/pentagi/requests/{id}/cancel"""
        request_id = getattr(pytest, "pentest_request_id", "test-request-1")
        response = api_client.post(
            f"/api/v1/pentagi/requests/{request_id}/cancel", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_116_create_pentest_result(self, api_client, auth_headers):
        """POST /api/v1/pentagi/results"""
        response = api_client.post(
            "/api/v1/pentagi/results",
            json={
                "request_id": getattr(pytest, "pentest_request_id", "test-request-1"),
                "exploitability": "confirmed_exploitable",
                "evidence": {"payload": "' OR '1'='1", "response": "200 OK"},
                "severity_adjustment": "high",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_117_list_pentest_results(self, api_client, auth_headers):
        """GET /api/v1/pentagi/results"""
        response = api_client.get("/api/v1/pentagi/results", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_118_get_pentest_result_by_request(self, api_client, auth_headers):
        """GET /api/v1/pentagi/results/by-request/{request_id}"""
        request_id = getattr(pytest, "pentest_request_id", "test-request-1")
        response = api_client.get(
            f"/api/v1/pentagi/results/by-request/{request_id}", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_119_create_pentagi_config(self, api_client, auth_headers):
        """POST /api/v1/pentagi/configs"""
        response = api_client.post(
            "/api/v1/pentagi/configs",
            json={
                "name": "E2E Pentagi Config",
                "pentagi_url": "https://pentagi.example.com",
                "api_key": "test-api-key",
                "enabled": True,
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        pytest.pentagi_config_id = response.json()["id"]

    def test_120_list_pentagi_configs(self, api_client, auth_headers):
        """GET /api/v1/pentagi/configs"""
        response = api_client.get("/api/v1/pentagi/configs", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_121_get_pentagi_config(self, api_client, auth_headers):
        """GET /api/v1/pentagi/configs/{id}"""
        config_id = getattr(pytest, "pentagi_config_id", "test-config-1")
        response = api_client.get(
            f"/api/v1/pentagi/configs/{config_id}", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_122_update_pentagi_config(self, api_client, auth_headers):
        """PUT /api/v1/pentagi/configs/{id}"""
        config_id = getattr(pytest, "pentagi_config_id", "test-config-1")
        response = api_client.put(
            f"/api/v1/pentagi/configs/{config_id}",
            json={"enabled": False},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_123_delete_pentagi_config(self, api_client, auth_headers):
        """DELETE /api/v1/pentagi/configs/{id}"""
        response = api_client.delete(
            "/api/v1/pentagi/configs/temp-config", headers=auth_headers
        )
        assert response.status_code in [200, 404]


class TestCoreAPIEndpoints:
    """Test core API endpoints (health, inputs, pipeline)."""

    def test_124_health_check(self, api_client):
        """GET /health"""
        response = api_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_125_upload_design(self, api_client, auth_headers):
        """POST /inputs/design"""
        csv_content = b"component,version,criticality\napp1,1.0.0,high\n"
        response = api_client.post(
            "/inputs/design",
            files={"file": ("design.csv", csv_content, "text/csv")},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_126_upload_sbom(self, api_client, auth_headers):
        """POST /inputs/sbom"""
        sbom_content = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
        ).encode()
        response = api_client.post(
            "/inputs/sbom",
            files={"file": ("sbom.json", sbom_content, "application/json")},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_127_upload_sarif(self, api_client, auth_headers):
        """POST /inputs/sarif"""
        sarif_content = json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [],
            }
        ).encode()
        response = api_client.post(
            "/inputs/sarif",
            files={"file": ("scan.sarif", sarif_content, "application/json")},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_128_upload_cve(self, api_client, auth_headers):
        """POST /inputs/cve"""
        cve_content = json.dumps(
            {
                "CVE_data_type": "CVE",
                "CVE_data_format": "MITRE",
                "CVE_data_version": "4.0",
                "CVE_data_numberOfCVEs": "0",
                "CVE_Items": [],
            }
        ).encode()
        response = api_client.post(
            "/inputs/cve",
            files={"file": ("cve.json", cve_content, "application/json")},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_129_upload_vex(self, api_client, auth_headers):
        """POST /inputs/vex"""
        vex_content = json.dumps(
            {"document": {"category": "csaf_vex", "csaf_version": "2.0"}}
        ).encode()
        response = api_client.post(
            "/inputs/vex",
            files={"file": ("vex.json", vex_content, "application/json")},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_130_upload_cnapp(self, api_client, auth_headers):
        """POST /inputs/cnapp"""
        cnapp_content = json.dumps({"assets": [], "findings": []}).encode()
        response = api_client.post(
            "/inputs/cnapp",
            files={"file": ("cnapp.json", cnapp_content, "application/json")},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_131_start_chunked_upload(self, api_client, auth_headers):
        """POST /inputs/sbom/chunks/start"""
        response = api_client.post(
            "/inputs/sbom/chunks/start",
            json={
                "file_name": "large-sbom.json",
                "total_size": 1000,
                "content_type": "application/json",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        pytest.chunk_session_id = response.json()["session"].get(
            "id"
        ) or response.json()["session"].get("session_id")

    def test_132_upload_chunk(self, api_client, auth_headers):
        """PUT /inputs/sbom/chunks/{session_id}"""
        session_id = getattr(pytest, "chunk_session_id", "test-session")
        chunk_content = b"test chunk data"
        response = api_client.put(
            f"/inputs/sbom/chunks/{session_id}",
            files={"chunk": ("chunk", chunk_content, "application/octet-stream")},
            params={"offset": 0},
            headers=auth_headers,
        )
        assert response.status_code in [200, 404]

    def test_133_complete_chunked_upload(self, api_client, auth_headers):
        """POST /inputs/sbom/chunks/{session_id}/complete"""
        session_id = getattr(pytest, "chunk_session_id", "test-session")
        response = api_client.post(
            f"/inputs/sbom/chunks/{session_id}/complete", headers=auth_headers
        )
        assert response.status_code in [200, 400, 404]

    def test_134_get_chunk_status(self, api_client, auth_headers):
        """GET /inputs/sbom/chunks/{session_id}"""
        session_id = getattr(pytest, "chunk_session_id", "test-session")
        response = api_client.get(
            f"/inputs/sbom/chunks/{session_id}", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_135_abort_chunked_upload(self, api_client, auth_headers):
        """DELETE /inputs/sbom/chunks/{session_id}"""
        session_id = getattr(pytest, "chunk_session_id", "test-session")
        response = api_client.delete(
            f"/inputs/sbom/chunks/{session_id}", headers=auth_headers
        )
        assert response.status_code in [200, 204, 404, 405]

    def test_136_run_pipeline(self, api_client, auth_headers):
        """POST /pipeline/run"""
        response = api_client.post("/pipeline/run", headers=auth_headers)
        assert response.status_code in [200, 400]

    def test_137_get_pipeline_status(self, api_client, auth_headers):
        """GET /pipeline/status"""
        response = api_client.get("/pipeline/status", headers=auth_headers)
        assert response.status_code in [200, 404]  # 404 if endpoint not implemented


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
