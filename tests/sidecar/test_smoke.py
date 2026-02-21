"""
FixOps API Smoke Tests - Sidecar Container
Tests all key API endpoints against a running FixOps instance.

These tests are designed to run in a Docker environment with a 'fixops' hostname.
They are skipped when FIXOPS_BASE_URL is not explicitly set (indicating local dev).
"""
import os
import time

import httpx
import pytest

BASE_URL = os.getenv("FIXOPS_BASE_URL", "http://fixops:8000")
API_KEY = os.getenv("FIXOPS_API_TOKEN", "test-token")
TIMEOUT = 30.0

# Skip all tests in this module if FIXOPS_BASE_URL is not explicitly set
# (default value indicates Docker environment which may not be available)
pytestmark = pytest.mark.skipif(
    os.getenv("FIXOPS_BASE_URL") is None,
    reason="Sidecar smoke tests require FIXOPS_BASE_URL to be set (Docker environment)",
)


def wait_for_health(timeout=120):
    """Wait for the API to become healthy."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{BASE_URL}/health", timeout=5.0)
            if r.status_code == 200:
                print(f"API is healthy: {r.json()}")
                return
        except Exception as e:
            print(f"Waiting for API... ({e})")
        time.sleep(3)
    raise RuntimeError("API never became healthy")


@pytest.fixture(scope="session")
def client():
    """Create an HTTP client with authentication."""
    wait_for_health()
    return httpx.Client(
        base_url=BASE_URL, headers={"X-API-Key": API_KEY}, timeout=TIMEOUT
    )


# =============================================================================
# Health & Status Endpoints
# =============================================================================


def test_health(client):
    """Test /health endpoint."""
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") in ("healthy", "ok")
    print(f"PASS: /health - {data}")


def test_api_status(client):
    """Test /api/v1/status endpoint."""
    r = client.get("/api/v1/status")
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") in ("ok", "healthy")
    print(f"PASS: /api/v1/status - {data}")


# =============================================================================
# Enhanced Capabilities
# =============================================================================


def test_enhanced_capabilities(client):
    """Test /api/v1/enhanced/capabilities endpoint."""
    r = client.get("/api/v1/enhanced/capabilities")
    assert r.status_code == 200
    data = r.json()
    assert "supported_llms" in data
    assert "knowledge_graph" in data
    print(f"PASS: /api/v1/enhanced/capabilities - LLMs: {data.get('supported_llms')}")


# =============================================================================
# Reachability Analysis
# =============================================================================


def test_reachability_health(client):
    """Test /api/v1/reachability/health endpoint."""
    r = client.get("/api/v1/reachability/health")
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") in (
        "healthy",
        "ok",
        "unhealthy",
    )  # unhealthy is valid if components not configured
    assert "components" in data
    print(f"PASS: /api/v1/reachability/health - {data.get('status')}")


def test_reachability_metrics(client):
    """Test /api/v1/reachability/metrics endpoint."""
    r = client.get("/api/v1/reachability/metrics")
    assert r.status_code == 200
    data = r.json()
    assert "timestamp" in data
    assert "storage" in data or "job_queue" in data
    print("PASS: /api/v1/reachability/metrics")


def test_reachability_analyze(client):
    """Test /api/v1/reachability/analyze endpoint - queues a job."""
    payload = {
        "cve_id": "CVE-2021-44228",
        "repository": {"url": "https://github.com/example/test-repo", "branch": "main"},
        "vulnerability": {
            "cve_id": "CVE-2021-44228",
            "component_name": "log4j-core",
            "component_version": "2.14.1",
            "vulnerable_function": "lookup",
        },
    }
    r = client.post("/api/v1/reachability/analyze", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert "job_id" in data
    assert data.get("status") in ("queued", "processing", "completed", "failed")
    print(f"PASS: /api/v1/reachability/analyze - job_id: {data.get('job_id')}")


# =============================================================================
# MPTE Endpoints
# =============================================================================


def test_mpte_stats(client):
    """Test /api/v1/mpte/stats endpoint."""
    r = client.get("/api/v1/mpte/stats")
    assert r.status_code == 200
    data = r.json()
    assert "total_requests" in data or "total_results" in data
    print("PASS: /api/v1/mpte/stats")


def test_mpte_configs(client):
    """Test /api/v1/mpte/configs endpoint."""
    r = client.get("/api/v1/mpte/configs")
    assert r.status_code == 200
    # Response could be empty list or list of configs
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/mpte/configs - {len(data)} configs")


def test_mpte_requests(client):
    """Test /api/v1/mpte/requests endpoint."""
    r = client.get("/api/v1/mpte/requests")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/mpte/requests - {len(data)} requests")


def test_mpte_results(client):
    """Test /api/v1/mpte/results endpoint."""
    r = client.get("/api/v1/mpte/results")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/mpte/results - {len(data)} results")


def test_mpte_monitoring(client):
    """Test /api/v1/mpte/monitoring endpoint."""
    r = client.get("/api/v1/mpte/monitoring")
    assert r.status_code == 200
    print("PASS: /api/v1/mpte/monitoring")


# =============================================================================
# Analytics Endpoints
# =============================================================================


def test_analytics_dashboard_overview(client):
    """Test /api/v1/analytics/dashboard/overview endpoint."""
    r = client.get("/api/v1/analytics/dashboard/overview")
    assert r.status_code == 200
    print("PASS: /api/v1/analytics/dashboard/overview")


def test_analytics_dashboard_trends(client):
    """Test /api/v1/analytics/dashboard/trends endpoint."""
    r = client.get("/api/v1/analytics/dashboard/trends")
    assert r.status_code == 200
    print("PASS: /api/v1/analytics/dashboard/trends")


def test_analytics_dashboard_top_risks(client):
    """Test /api/v1/analytics/dashboard/top-risks endpoint."""
    r = client.get("/api/v1/analytics/dashboard/top-risks")
    assert r.status_code == 200
    print("PASS: /api/v1/analytics/dashboard/top-risks")


# =============================================================================
# Inventory Endpoints
# =============================================================================


def test_inventory_applications(client):
    """Test /api/v1/inventory/applications endpoint."""
    r = client.get("/api/v1/inventory/applications")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/inventory/applications - {len(data)} apps")


def test_inventory_services(client):
    """Test /api/v1/inventory/services endpoint."""
    r = client.get("/api/v1/inventory/services")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/inventory/services - {len(data)} services")


def test_inventory_apis(client):
    """Test /api/v1/inventory/apis endpoint."""
    r = client.get("/api/v1/inventory/apis")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/inventory/apis - {len(data)} APIs")


# =============================================================================
# Policies Endpoints
# =============================================================================


def test_policies_list(client):
    """Test /api/v1/policies endpoint."""
    r = client.get("/api/v1/policies")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/policies - {len(data)} policies")


# =============================================================================
# Integrations Endpoints
# =============================================================================


def test_integrations_list(client):
    """Test /api/v1/integrations endpoint."""
    r = client.get("/api/v1/integrations")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/integrations - {len(data)} integrations")


# =============================================================================
# Secrets Endpoints
# =============================================================================


def test_secrets_list(client):
    """Test /api/v1/secrets endpoint."""
    r = client.get("/api/v1/secrets")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/secrets - {len(data)} secrets")


# =============================================================================
# Reports Endpoints
# =============================================================================


def test_reports_list(client):
    """Test /api/v1/reports endpoint."""
    r = client.get("/api/v1/reports")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/reports - {len(data)} reports")


def test_reports_templates(client):
    """Test /api/v1/reports/templates/list endpoint."""
    r = client.get("/api/v1/reports/templates/list")
    assert r.status_code == 200
    print("PASS: /api/v1/reports/templates/list")


def test_reports_schedules(client):
    """Test /api/v1/reports/schedules/list endpoint."""
    r = client.get("/api/v1/reports/schedules/list")
    assert r.status_code == 200
    print("PASS: /api/v1/reports/schedules/list")


# =============================================================================
# Audit Endpoints
# =============================================================================


def test_audit_logs(client):
    """Test /api/v1/audit/logs endpoint."""
    r = client.get("/api/v1/audit/logs")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/audit/logs - {len(data)} logs")


def test_audit_compliance_frameworks(client):
    """Test /api/v1/audit/compliance/frameworks endpoint."""
    r = client.get("/api/v1/audit/compliance/frameworks")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/audit/compliance/frameworks - {len(data)} frameworks")


def test_audit_compliance_controls(client):
    """Test /api/v1/audit/compliance/controls endpoint."""
    r = client.get("/api/v1/audit/compliance/controls")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/audit/compliance/controls - {len(data)} controls")


# =============================================================================
# Teams & Users Endpoints
# =============================================================================


def test_teams_list(client):
    """Test /api/v1/teams endpoint."""
    r = client.get("/api/v1/teams")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/teams - {len(data)} teams")


def test_users_list(client):
    """Test /api/v1/users endpoint."""
    r = client.get("/api/v1/users")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/users - {len(data)} users")


# =============================================================================
# Workflows Endpoints
# =============================================================================


def test_workflows_list(client):
    """Test /api/v1/workflows endpoint."""
    r = client.get("/api/v1/workflows")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/workflows - {len(data)} workflows")


# =============================================================================
# IAC Endpoints
# =============================================================================


def test_iac_list(client):
    """Test /api/v1/iac endpoint."""
    r = client.get("/api/v1/iac")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/iac - {len(data)} IAC findings")


# =============================================================================
# Triage Endpoints
# =============================================================================


def test_triage_list(client):
    """Test /api/v1/triage endpoint."""
    r = client.get("/api/v1/triage")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    print(f"PASS: /api/v1/triage - {len(data)} triage items")


# =============================================================================
# Graph Endpoints
# =============================================================================


def test_graph_root(client):
    """Test /graph/ endpoint."""
    r = client.get("/graph/")
    assert r.status_code == 200
    print("PASS: /graph/")


def test_graph_anomalies(client):
    """Test /graph/anomalies endpoint."""
    r = client.get("/graph/anomalies")
    assert r.status_code == 200
    print("PASS: /graph/anomalies")


def test_graph_kev_components(client):
    """Test /graph/kev-components endpoint."""
    r = client.get("/graph/kev-components")
    assert r.status_code == 200
    print("PASS: /graph/kev-components")


# =============================================================================
# Evidence Endpoints
# =============================================================================


def test_evidence_root(client):
    """Test /evidence/ endpoint."""
    r = client.get("/evidence/")
    assert r.status_code == 200
    print("PASS: /evidence/")


# =============================================================================
# Provenance Endpoints
# =============================================================================


def test_provenance_root(client):
    """Test /provenance/ endpoint."""
    r = client.get("/provenance/")
    assert r.status_code == 200
    print("PASS: /provenance/")


# =============================================================================
# Risk Endpoints
# =============================================================================


def test_risk_root(client):
    """Test /risk/ endpoint."""
    r = client.get("/risk/")
    assert r.status_code == 200
    print("PASS: /risk/")


# =============================================================================
# Pipeline Demo Flow (Full Integration Test)
# =============================================================================


def test_pipeline_requires_artifacts(client):
    """Test that /pipeline/run requires artifacts to be uploaded first."""
    r = client.get("/pipeline/run")
    # Should return 400 with missing artifacts message
    assert r.status_code == 400
    data = r.json()
    assert "detail" in data
    assert "missing" in str(data).lower() or "artefacts" in str(data).lower()
    print("PASS: /pipeline/run correctly requires artifacts")


# =============================================================================
# OpenAPI Spec Validation
# =============================================================================


def test_openapi_spec(client):
    """Test that OpenAPI spec is available and valid."""
    r = client.get("/openapi.json")
    assert r.status_code == 200
    data = r.json()
    assert "paths" in data
    assert "info" in data
    endpoint_count = len(data.get("paths", {}))
    print(f"PASS: /openapi.json - {endpoint_count} endpoints documented")
    assert endpoint_count >= 100, f"Expected 100+ endpoints, got {endpoint_count}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
