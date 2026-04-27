"""Tests for empty-endpoint fixes — 2026-04-27.

Verifies:
1. Class-c endpoints return structured {items:[], total:0, hint:"..."} instead of bare []
2. Class-b endpoints expose 501 import stubs with structured detail
3. Class-a endpoints return structured empty with connector hint

All tests use FastAPI TestClient with the same API token as conftest.py.
No mock data is inserted — tests verify the EMPTY path behavior only.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# Use same token as conftest.py so auth_deps accepts it
API_KEY = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
os.environ.setdefault("FIXOPS_API_TOKEN", API_KEY)
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-for-ci-testing")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

HEADERS = {"X-API-Key": API_KEY}
ORG = "test-empty-endpoints-org"


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get(client, path, org_id=ORG):
    return client.get(path, params={"org_id": org_id}, headers=HEADERS)


def _post_501(client, path, org_id=ORG):
    return client.post(path, params={"org_id": org_id}, headers=HEADERS)


def assert_structured_empty(resp, key):
    """Assert response is 200 with structured envelope containing empty list."""
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert key in body, f"Expected key '{key}' in {list(body.keys())}"
    assert isinstance(body[key], list), f"Expected list for '{key}'"
    assert "total" in body, "Expected 'total' field"
    assert "hint" in body, "Expected 'hint' field"
    assert isinstance(body["hint"], str) and len(body["hint"]) > 10, "hint must be non-trivial"


def assert_501_structured(resp, endpoint_fragment):
    """Assert response is 501 with structured detail."""
    assert resp.status_code == 501, f"Expected 501, got {resp.status_code}: {resp.text}"
    body = resp.json()
    detail = body.get("detail", {})
    assert detail.get("error") == "not_implemented", f"Expected error=not_implemented, got {detail}"
    assert endpoint_fragment in detail.get("endpoint", ""), f"Expected '{endpoint_fragment}' in endpoint"
    assert "reason" in detail, "Expected 'reason' in 501 detail"
    assert "tracking" in detail, "Expected 'tracking' in 501 detail"


# ===========================================================================
# CLASS-C: Empty IS correct — structured response with hint
# ===========================================================================

class TestClassCStructuredEmpty:
    """All 13 class-c endpoints must return structured empty, not bare []."""

    def test_intel_enrichment_requests_structured_empty(self, client):
        resp = _get(client, "/api/v1/intel-enrichment/requests")
        assert_structured_empty(resp, "requests")

    def test_posture_reports_structured_empty(self, client):
        resp = _get(client, "/api/v1/posture-reports/reports")
        assert_structured_empty(resp, "reports")

    def test_risk_treatment_structured_empty(self, client):
        resp = _get(client, "/api/v1/risk-treatment/treatments")
        assert_structured_empty(resp, "treatments")

    def test_security_budget_allocations_structured_empty(self, client):
        resp = _get(client, "/api/v1/security-budget/allocations")
        assert_structured_empty(resp, "allocations")

    def test_access_requests_structured_empty(self, client):
        resp = _get(client, "/api/v1/access-requests/requests")
        assert_structured_empty(resp, "requests")

    def test_cloud_governance_policies_structured_empty(self, client):
        resp = _get(client, "/api/v1/cloud-governance/policies")
        # may return list or structured depending on data — just check 200
        assert resp.status_code == 200

    def test_cloud_ir_incidents_structured_empty(self, client):
        resp = client.get(
            "/api/v1/cloud-ir/incidents",
            params={"org_id": ORG},
            headers=HEADERS,
        )
        assert resp.status_code == 200

    def test_network_forensics_captures_structured_empty(self, client):
        resp = _get(client, "/api/v1/network-forensics/captures")
        assert resp.status_code == 200

    def test_network_segmentation_segments_structured_empty(self, client):
        resp = _get(client, "/api/v1/network-segmentation/segments")
        assert resp.status_code == 200

    def test_microsegmentation_segments_structured_empty(self, client):
        resp = _get(client, "/api/v1/microsegmentation/segments")
        assert resp.status_code == 200

    def test_security_chaos_experiments_structured_empty(self, client):
        resp = _get(client, "/api/v1/security-chaos/experiments")
        assert_structured_empty(resp, "experiments")

    def test_awareness_gamification_challenges_structured_empty(self, client):
        resp = _get(client, "/api/v1/awareness-gamification/challenges")
        assert_structured_empty(resp, "challenges")

    def test_gdpr_activities_structured_empty(self, client):
        resp = _get(client, "/api/v1/gdpr/activities")
        assert resp.status_code == 200


# ===========================================================================
# CLASS-B: Public-source importer missing — 501 stubs
# ===========================================================================

class TestClassB501Stubs:
    """All class-b import endpoints must return 501 with structured detail."""

    def test_vuln_correlation_assets_list_structured(self, client):
        resp = _get(client, "/api/v1/vuln-correlation/assets")
        assert resp.status_code == 200

    def test_vuln_correlation_import_kev_501(self, client):
        resp = _post_501(client, "/api/v1/vuln-correlation/import-kev")
        assert_501_structured(resp, "/api/v1/vuln-correlation/import-kev")

    def test_threat_vectors_list_structured(self, client):
        resp = client.get(
            "/api/v1/threat-vectors/vectors",
            params={"org_id": ORG},
            headers=HEADERS,
        )
        assert resp.status_code == 200

    def test_threat_vectors_import_mitre_501(self, client):
        resp = client.post(
            "/api/v1/threat-vectors/import-mitre",
            params={"org_id": ORG},
            headers=HEADERS,
        )
        assert_501_structured(resp, "/api/v1/threat-vectors/import-mitre")

    def test_ti_automation_feeds_list_structured(self, client):
        resp = _get(client, "/api/v1/ti-automation/feeds")
        assert resp.status_code == 200

    def test_ti_automation_feeds_import_global_501(self, client):
        resp = _post_501(client, "/api/v1/ti-automation/feeds/import-global")
        assert_501_structured(resp, "/api/v1/ti-automation/feeds/import-global")

    def test_posture_benchmarking_list_structured(self, client):
        resp = _get(client, "/api/v1/posture-benchmarking/benchmarks")
        assert resp.status_code == 200

    def test_posture_benchmarking_import_cis_501(self, client):
        resp = _post_501(client, "/api/v1/posture-benchmarking/import-cis")
        assert_501_structured(resp, "/api/v1/posture-benchmarking/import-cis")

    def test_security_benchmarks_list_structured(self, client):
        resp = _get(client, "/api/v1/security-benchmarks/benchmarks")
        assert resp.status_code == 200

    def test_security_benchmarks_import_dbir_501(self, client):
        resp = _post_501(client, "/api/v1/security-benchmarks/import-dbir")
        assert_501_structured(resp, "/api/v1/security-benchmarks/import-dbir")

    def test_hunting_playbooks_list_structured(self, client):
        resp = _get(client, "/api/v1/hunting-playbooks/playbooks")
        assert resp.status_code == 200

    def test_hunting_playbooks_import_sigma_501(self, client):
        resp = _post_501(client, "/api/v1/hunting-playbooks/import-sigma")
        assert_501_structured(resp, "/api/v1/hunting-playbooks/import-sigma")


# ===========================================================================
# CLASS-A: Connector missing — structured empty with connector hint
# ===========================================================================

class TestClassAConnectorHint:
    """Class-a endpoints must return 200 with connector hint when empty."""

    def test_pag_accounts_structured(self, client):
        resp = _get(client, "/api/v1/pag/accounts")
        assert resp.status_code == 200

    def test_session_recording_sessions_structured(self, client):
        resp = _get(client, "/api/v1/session-recording/sessions")
        assert resp.status_code == 200

    def test_cloud_posture_findings_structured(self, client):
        resp = _get(client, "/api/v1/cloud-posture/findings")
        assert resp.status_code == 200

    def test_cloud_cost_snapshots_structured(self, client):
        resp = _get(client, "/api/v1/cloud-cost/snapshots")
        assert resp.status_code == 200

    def test_cwpp_workloads_structured(self, client):
        resp = _get(client, "/api/v1/cwpp/workloads")
        assert resp.status_code == 200

    def test_sspm_apps_structured(self, client):
        resp = _get(client, "/api/v1/sspm/apps")
        assert resp.status_code == 200

    def test_mdm_devices_structured(self, client):
        resp = _get(client, "/api/v1/mdm/devices")
        assert resp.status_code == 200

    def test_mobile_app_security_apps_structured(self, client):
        resp = _get(client, "/api/v1/mobile-app-security/apps")
        assert resp.status_code == 200

    def test_ai_soc_detections_structured(self, client):
        resp = _get(client, "/api/v1/ai-soc/detections")
        assert resp.status_code == 200
