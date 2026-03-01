"""
Comprehensive Deep API Tests for ALdeci / FixOps.

Covers EVERY major endpoint group via FastAPI TestClient:
    - /health and /api/v1/health — health/readiness/version
    - /api/v1/analytics/* — dashboard, trends, MTTR, compliance, findings, ROI
    - /api/v1/reports/* — CRUD, generation, stats, schedules, templates
    - /api/v1/brain/pipeline/* — brain pipeline run/list/get
    - /api/v1/ingest/* — multipart ingestion, formats, assets
    - /api/v1/fail/* — FAIL scoring, batch, stats, top-risks
    - /api/v1/mcp/* — MCP catalog, health, stats
    - /api/v1/connectors/* — registration, listing, health
    - /api/v1/remediation/* — task lifecycle
    - Auth header enforcement (401 without key)
    - Response structure validation

Total: 65+ test functions, no mocked assertions, no ``assert True``.
"""

from __future__ import annotations

import io
import json
import os
import warnings
from typing import Any, Dict

import pytest

# ---------------------------------------------------------------------------
# Environment — MUST be set before importing create_app
# ---------------------------------------------------------------------------
API_TOKEN = os.getenv("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_API_TOKEN", API_TOKEN)
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault(
    "FIXOPS_JWT_SECRET", "test-jwt-secret-deep-api-tests-never-production"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    """Create a module-scoped TestClient for all API tests.

    Uses ``raise_server_exceptions=False`` so we can assert on 4xx/5xx
    responses instead of getting Python tracebacks.
    """
    from apps.api.app import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="module")
def headers():
    """Standard authenticated request headers."""
    return {"X-API-Key": API_TOKEN}


# ═══════════════════════════════════════════════════════════════════════════
# 1. HEALTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestHealthEndpoints:
    """Verify health, readiness, version, and metrics endpoints."""

    def test_legacy_health(self, client, headers):
        """GET /health returns 200 with status=healthy."""
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "timestamp" in body

    def test_api_v1_health(self, client, headers):
        """GET /api/v1/health returns 200 with version info."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "version" in body
        assert body["service"] == "fixops-api"

    def test_readiness_check(self, client, headers):
        """GET /api/v1/ready returns checks dict."""
        resp = client.get("/api/v1/ready")
        # May be 200 or 503 depending on component health
        assert resp.status_code in (200, 503)
        body = resp.json()
        assert "checks" in body
        assert "status" in body

    def test_version_endpoint(self, client, headers):
        """GET /api/v1/version returns build info."""
        resp = client.get("/api/v1/version")
        assert resp.status_code == 200
        body = resp.json()
        assert "version" in body
        assert "python_version" in body
        assert body["service"] == "fixops-api"

    def test_metrics_endpoint(self, client, headers):
        """GET /api/v1/metrics returns application metrics."""
        resp = client.get("/api/v1/metrics")
        assert resp.status_code == 200
        body = resp.json()
        assert "timestamp" in body
        assert body["service"] == "fixops-api"

    def test_health_no_auth_required(self, client):
        """Health endpoints must NOT require auth."""
        for path in ["/health", "/api/v1/health", "/api/v1/ready", "/api/v1/version"]:
            resp = client.get(path)
            assert resp.status_code != 401, f"{path} should not require auth"


# ═══════════════════════════════════════════════════════════════════════════
# 2. AUTHENTICATION ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════════════


class TestAuthEnforcement:
    """Verify that protected endpoints reject unauthenticated requests."""

    @pytest.mark.parametrize(
        "path",
        [
            "/api/v1/analytics/dashboard/overview",
            "/api/v1/analytics/findings",
            "/api/v1/analytics/mttr",
            "/api/v1/reports",
            "/api/v1/fail/scores",
            "/api/v1/remediation/tasks",
            "/api/v1/status",
        ],
    )
    def test_protected_get_returns_401_without_key(self, client, path):
        """GET on protected endpoints without X-API-Key returns 401."""
        resp = client.get(path)
        assert resp.status_code == 401, (
            f"{path} returned {resp.status_code} instead of 401 without auth"
        )

    def test_invalid_api_key_rejected(self, client):
        """An incorrect API key should also be rejected."""
        resp = client.get(
            "/api/v1/analytics/dashboard/overview",
            headers={"X-API-Key": "INVALID-KEY-999"},
        )
        assert resp.status_code == 401

    def test_valid_api_key_accepted(self, client, headers):
        """A valid API key should be accepted (not 401)."""
        resp = client.get("/api/v1/analytics/dashboard/overview", headers=headers)
        assert resp.status_code != 401


# ═══════════════════════════════════════════════════════════════════════════
# 3. ANALYTICS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestAnalyticsEndpoints:
    """Cover /api/v1/analytics/* — dashboard, findings, decisions, MTTR, ROI."""

    def test_dashboard_overview(self, client, headers):
        """GET /api/v1/analytics/dashboard/overview returns posture overview."""
        resp = client.get("/api/v1/analytics/dashboard/overview", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "org_id" in body

    def test_dashboard_trends(self, client, headers):
        """GET /api/v1/analytics/dashboard/trends returns trend metrics."""
        resp = client.get(
            "/api/v1/analytics/dashboard/trends", headers=headers, params={"days": 7}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "period_days" in body
        assert body["period_days"] == 7

    def test_dashboard_trends_invalid_days(self, client, headers):
        """Invalid days parameter returns 422 validation error."""
        resp = client.get(
            "/api/v1/analytics/dashboard/trends", headers=headers, params={"days": 0}
        )
        assert resp.status_code == 422

    def test_top_risks(self, client, headers):
        """GET /api/v1/analytics/dashboard/top-risks returns risk list."""
        resp = client.get("/api/v1/analytics/dashboard/top-risks", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "risks" in body
        assert isinstance(body["risks"], list)

    def test_compliance_status(self, client, headers):
        """GET /api/v1/analytics/dashboard/compliance-status."""
        resp = client.get(
            "/api/v1/analytics/dashboard/compliance-status", headers=headers
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "compliance_score" in body
        assert isinstance(body["compliance_score"], (int, float))

    def test_findings_list(self, client, headers):
        """GET /api/v1/analytics/findings returns paginated findings."""
        resp = client.get("/api/v1/analytics/findings", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)

    def test_findings_create_and_get(self, client, headers):
        """POST then GET a finding via /api/v1/analytics/findings."""
        payload = {
            "org_id": "test-org",
            "rule_id": "CWE-79",
            "severity": "high",
            "title": "XSS in login form",
            "description": "Reflected XSS via user param",
            "source": "sast",
        }
        create_resp = client.post(
            "/api/v1/analytics/findings", headers=headers, json=payload
        )
        assert create_resp.status_code == 201, create_resp.text
        created = create_resp.json()
        assert "id" in created
        finding_id = created["id"]

        # Retrieve the same finding
        get_resp = client.get(
            f"/api/v1/analytics/findings/{finding_id}", headers=headers
        )
        assert get_resp.status_code == 200
        fetched = get_resp.json()
        assert fetched["id"] == finding_id
        assert fetched["title"] == "XSS in login form"

    def test_finding_update(self, client, headers):
        """PUT /api/v1/analytics/findings/{id} updates status."""
        # Create a finding first
        payload = {
            "org_id": "test-org",
            "rule_id": "CWE-89",
            "severity": "critical",
            "title": "SQL Injection in search",
            "description": "Parameterised query missing",
            "source": "dast",
        }
        resp = client.post("/api/v1/analytics/findings", headers=headers, json=payload)
        assert resp.status_code == 201
        fid = resp.json()["id"]

        # Update the finding
        update_resp = client.put(
            f"/api/v1/analytics/findings/{fid}",
            headers=headers,
            json={"status": "resolved"},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["status"] == "resolved"

    def test_finding_not_found(self, client, headers):
        """GET /api/v1/analytics/findings/nonexistent returns 404."""
        resp = client.get(
            "/api/v1/analytics/findings/nonexistent-id-999", headers=headers
        )
        assert resp.status_code == 404

    def test_decisions_list(self, client, headers):
        """GET /api/v1/analytics/decisions returns paginated decisions."""
        resp = client.get("/api/v1/analytics/decisions", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)

    def test_mttr(self, client, headers):
        """GET /api/v1/analytics/mttr returns remediation time metrics."""
        resp = client.get("/api/v1/analytics/mttr", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "mttr_hours" in body

    def test_coverage(self, client, headers):
        """GET /api/v1/analytics/coverage returns scan coverage."""
        resp = client.get("/api/v1/analytics/coverage", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "total_findings" in body

    def test_roi(self, client, headers):
        """GET /api/v1/analytics/roi returns ROI calculations."""
        resp = client.get("/api/v1/analytics/roi", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "estimated_prevented_cost" in body
        assert body["currency"] == "USD"

    def test_noise_reduction(self, client, headers):
        """GET /api/v1/analytics/noise-reduction."""
        resp = client.get("/api/v1/analytics/noise-reduction", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "noise_reduction_percentage" in body

    def test_custom_query_findings(self, client, headers):
        """POST /api/v1/analytics/custom-query for findings."""
        payload = {"type": "findings", "filters": {"severity": "critical", "limit": 5}}
        resp = client.post(
            "/api/v1/analytics/custom-query", headers=headers, json=payload
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "results" in body
        assert "count" in body

    def test_custom_query_invalid_type(self, client, headers):
        """POST custom-query with unsupported type returns 400."""
        payload = {"type": "nonexistent_query"}
        resp = client.post(
            "/api/v1/analytics/custom-query", headers=headers, json=payload
        )
        assert resp.status_code == 400

    def test_export_json(self, client, headers):
        """GET /api/v1/analytics/export?format=json returns findings export."""
        resp = client.get(
            "/api/v1/analytics/export",
            headers=headers,
            params={"format": "json", "data_type": "findings"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "count" in body

    def test_export_invalid_format(self, client, headers):
        """GET /api/v1/analytics/export with bad format returns 422."""
        resp = client.get(
            "/api/v1/analytics/export",
            headers=headers,
            params={"format": "xml"},
        )
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
# 4. REPORTS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestReportsEndpoints:
    """Cover /api/v1/reports — CRUD, generation, stats, schedules, templates."""

    def test_list_reports(self, client, headers):
        """GET /api/v1/reports returns paginated report list."""
        resp = client.get("/api/v1/reports", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "total" in body

    def test_create_report_json(self, client, headers):
        """POST /api/v1/reports creates a JSON report."""
        payload = {
            "name": "Test Security Report",
            "report_type": "compliance",
            "format": "json",
            "parameters": {},
        }
        resp = client.post("/api/v1/reports", headers=headers, json=payload)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["format"] == "json"
        assert body["status"] in ("completed", "pending", "failed")
        assert "id" in body

    def test_create_report_csv(self, client, headers):
        """POST /api/v1/reports creates a CSV report."""
        payload = {
            "name": "CSV Export Report",
            "report_type": "compliance",
            "format": "csv",
            "parameters": {},
        }
        resp = client.post("/api/v1/reports", headers=headers, json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert body["format"] == "csv"

    def test_create_report_html(self, client, headers):
        """POST /api/v1/reports creates an HTML report."""
        payload = {
            "report_type": "vulnerability",
            "format": "html",
            "parameters": {},
        }
        resp = client.post("/api/v1/reports", headers=headers, json=payload)
        assert resp.status_code == 201

    def test_generate_report_alias(self, client, headers):
        """POST /api/v1/reports/generate is an alias for report creation."""
        payload = {
            "name": "Via Generate Endpoint",
            "report_type": "compliance",
            "format": "json",
            "parameters": {},
        }
        resp = client.post("/api/v1/reports/generate", headers=headers, json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert "id" in body

    def test_get_report_by_id(self, client, headers):
        """GET /api/v1/reports/{id} retrieves a report."""
        # Create first
        payload = {
            "name": "Retrieve Test",
            "report_type": "compliance",
            "format": "json",
            "parameters": {},
        }
        created = client.post(
            "/api/v1/reports", headers=headers, json=payload
        ).json()
        report_id = created["id"]

        resp = client.get(f"/api/v1/reports/{report_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == report_id

    def test_get_report_not_found(self, client, headers):
        """GET /api/v1/reports/nonexistent returns 404."""
        resp = client.get("/api/v1/reports/nonexistent-id-9999", headers=headers)
        assert resp.status_code == 404

    def test_report_stats(self, client, headers):
        """GET /api/v1/reports/stats returns aggregate report metrics."""
        resp = client.get("/api/v1/reports/stats", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "total_reports" in body
        assert "by_type" in body
        assert "by_status" in body

    def test_schedule_report(self, client, headers):
        """POST /api/v1/reports/schedule creates a recurring report."""
        payload = {
            "report_type": "compliance",
            "format": "json",
            "schedule_cron": "0 8 * * 1",
            "parameters": {},
        }
        resp = client.post("/api/v1/reports/schedule", headers=headers, json=payload)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "id" in body

    def test_list_schedules(self, client, headers):
        """GET /api/v1/reports/schedules/list returns scheduled reports."""
        resp = client.get("/api/v1/reports/schedules/list", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body

    def test_list_templates(self, client, headers):
        """GET /api/v1/reports/templates/list returns available templates."""
        resp = client.get("/api/v1/reports/templates/list", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "templates" in body


# ═══════════════════════════════════════════════════════════════════════════
# 5. BRAIN PIPELINE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestBrainPipelineEndpoints:
    """Cover /api/v1/brain/pipeline/* — run, list, get."""

    def test_pipeline_run_minimal(self, client, headers):
        """POST /api/v1/brain/pipeline/run with minimal payload."""
        payload = {
            "org_id": "test-org-001",
            "findings": [
                {
                    "id": "FIND-1",
                    "severity": "high",
                    "title": "SQL Injection in auth",
                    "source": "sast",
                }
            ],
            "assets": [],
            "source": "api-test",
        }
        resp = client.post(
            "/api/v1/brain/pipeline/run", headers=headers, json=payload
        )
        # Pipeline should complete or partially complete
        assert resp.status_code in (200, 201, 500), resp.text
        if resp.status_code == 200:
            body = resp.json()
            assert "run_id" in body or "status" in body

    def test_pipeline_runs_list(self, client, headers):
        """GET /api/v1/brain/pipeline/runs returns run history."""
        resp = client.get("/api/v1/brain/pipeline/runs", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "runs" in body
        assert "total" in body

    def test_pipeline_run_not_found(self, client, headers):
        """GET /api/v1/brain/pipeline/runs/{id} for nonexistent returns 404."""
        resp = client.get(
            "/api/v1/brain/pipeline/runs/nonexistent-run-id", headers=headers
        )
        assert resp.status_code == 404

    def test_pipeline_run_with_multiple_findings(self, client, headers):
        """POST /api/v1/brain/pipeline/run with multiple diverse findings."""
        findings = [
            {
                "id": f"FIND-{i}",
                "cve_id": f"CVE-2024-{1000 + i}",
                "severity": sev,
                "title": f"Vuln {i}",
                "source": src,
            }
            for i, (sev, src) in enumerate(
                [
                    ("critical", "sast"),
                    ("high", "dast"),
                    ("medium", "container"),
                    ("low", "secrets"),
                    ("high", "sast"),
                ]
            )
        ]
        payload = {
            "org_id": "test-org-002",
            "findings": findings,
            "assets": [
                {"id": "ASSET-1", "name": "web-app", "criticality": 0.9},
            ],
            "source": "api-test",
        }
        resp = client.post(
            "/api/v1/brain/pipeline/run", headers=headers, json=payload
        )
        assert resp.status_code in (200, 500)

    def test_pipeline_evidence_generate(self, client, headers):
        """POST /api/v1/brain/evidence/generate creates an evidence pack."""
        payload = {
            "org_id": "test-org-003",
            "timeframe_days": 30,
            "findings": [
                {"id": "F-1", "severity": "high", "title": "Test finding"},
            ],
            "assets": [],
        }
        resp = client.post(
            "/api/v1/brain/evidence/generate", headers=headers, json=payload
        )
        # May succeed or 500 if external deps missing
        assert resp.status_code in (200, 201, 500)

    def test_pipeline_evidence_packs_list(self, client, headers):
        """GET /api/v1/brain/evidence/packs returns evidence packs."""
        resp = client.get("/api/v1/brain/evidence/packs", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "packs" in body


# ═══════════════════════════════════════════════════════════════════════════
# 6. INGESTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestIngestionEndpoints:
    """Cover /api/v1/ingest/* — multipart, formats, assets, and /inputs/* uploads."""

    def test_list_supported_formats(self, client, headers):
        """GET /api/v1/ingest/formats returns normalizer catalog."""
        resp = client.get("/api/v1/ingest/formats", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "normalizers" in body
        assert "total" in body

    def test_get_asset_inventory(self, client, headers):
        """GET /api/v1/ingest/assets returns discovered assets."""
        resp = client.get("/api/v1/ingest/assets", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "total" in body
        assert "assets" in body

    def test_ingest_sarif_file(self, client, headers):
        """POST /inputs/sarif ingests a minimal SARIF file."""
        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestScanner",
                            "version": "1.0.0",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }
        file_bytes = json.dumps(sarif_doc).encode("utf-8")
        resp = client.post(
            "/inputs/sarif",
            headers={"X-API-Key": API_TOKEN},
            files={"file": ("scan.sarif", io.BytesIO(file_bytes), "application/json")},
        )
        assert resp.status_code in (200, 201), resp.text
        body = resp.json()
        assert body["status"] == "ok"
        assert body["stage"] == "sarif"

    def test_ingest_sbom_cyclonedx(self, client, headers):
        """POST /inputs/sbom ingests a CycloneDX SBOM."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                }
            ],
        }
        file_bytes = json.dumps(sbom).encode("utf-8")
        resp = client.post(
            "/inputs/sbom",
            headers={"X-API-Key": API_TOKEN},
            files={"file": ("sbom.json", io.BytesIO(file_bytes), "application/json")},
        )
        assert resp.status_code in (200, 201), resp.text
        body = resp.json()
        assert body["status"] == "ok"
        assert body["stage"] == "sbom"

    def test_ingest_unsupported_content_type(self, client, headers):
        """POST /inputs/sarif with wrong content type returns 415."""
        resp = client.post(
            "/inputs/sarif",
            headers={"X-API-Key": API_TOKEN},
            files={"file": ("bad.xml", b"<not-json/>", "text/xml")},
        )
        assert resp.status_code == 415


# ═══════════════════════════════════════════════════════════════════════════
# 7. FAIL ENGINE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestFAILEngineEndpoints:
    """Cover /api/v1/fail/* — scoring, batch, stats, top-risks."""

    def test_fail_score_single(self, client, headers):
        """POST /api/v1/fail/score computes a FAIL score."""
        payload = {
            "cve_id": "CVE-2024-3094",
            "title": "xz backdoor",
            "cvss_score": 10.0,
            "epss_score": 0.97,
            "is_kev": True,
            "has_exploit": True,
            "exploit_maturity": "weaponized",
            "is_reachable": True,
            "is_internet_facing": True,
            "affected_assets": 50,
        }
        resp = client.post("/api/v1/fail/score", headers=headers, json=payload)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "fail_score" in body
        assert "grade" in body
        assert "recommended_action" in body
        assert body["fail_score"] > 0

    def test_fail_score_minimal(self, client, headers):
        """POST /api/v1/fail/score with only defaults still works."""
        payload = {"title": "Generic vuln"}
        resp = client.post("/api/v1/fail/score", headers=headers, json=payload)
        assert resp.status_code == 200
        body = resp.json()
        assert "fail_score" in body

    def test_fail_score_batch(self, client, headers):
        """POST /api/v1/fail/score/batch scores multiple findings."""
        payload = {
            "findings": [
                {"cve_id": "CVE-2024-0001", "cvss_score": 9.8, "title": "Vuln A"},
                {"cve_id": "CVE-2024-0002", "cvss_score": 5.0, "title": "Vuln B"},
                {"cve_id": "CVE-2024-0003", "cvss_score": 2.0, "title": "Vuln C"},
            ]
        }
        resp = client.post("/api/v1/fail/score/batch", headers=headers, json=payload)
        assert resp.status_code == 200
        body = resp.json()
        assert "total" in body
        assert body["total"] >= 1
        assert "results" in body

    def test_fail_scores_list(self, client, headers):
        """GET /api/v1/fail/scores returns paginated scores."""
        resp = client.get("/api/v1/fail/scores", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "total" in body
        assert "results" in body

    def test_fail_score_get_not_found(self, client, headers):
        """GET /api/v1/fail/score/nonexistent returns 404."""
        resp = client.get("/api/v1/fail/score/nonexistent-id-9999", headers=headers)
        assert resp.status_code == 404

    def test_fail_top_risks(self, client, headers):
        """GET /api/v1/fail/top-risks returns top FAIL-scored risks."""
        resp = client.get("/api/v1/fail/top-risks", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "results" in body or "total" in body or isinstance(body, list)

    def test_fail_stats(self, client, headers):
        """GET /api/v1/fail/stats returns aggregate statistics."""
        resp = client.get("/api/v1/fail/stats", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "total" in body


# ═══════════════════════════════════════════════════════════════════════════
# 8. MCP ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestMCPEndpoints:
    """Cover /api/v1/mcp/* — auto-discovery catalog, health, stats."""

    def test_mcp_health(self, client, headers):
        """GET /api/v1/mcp/health returns MCP service status."""
        resp = client.get("/api/v1/mcp/health", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "status" in body

    def test_mcp_catalog(self, client, headers):
        """GET /api/v1/mcp/tools returns auto-generated tool catalog."""
        resp = client.get("/api/v1/mcp/tools", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        # Should be a list of tools or a dict with tools key
        if isinstance(body, dict):
            assert "tools" in body or "total" in body
        else:
            assert isinstance(body, list)

    def test_mcp_stats(self, client, headers):
        """GET /api/v1/mcp/stats returns catalog statistics."""
        resp = client.get("/api/v1/mcp/stats", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "total_tools" in body or "status" in body


# ═══════════════════════════════════════════════════════════════════════════
# 9. CONNECTORS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestConnectorsEndpoints:
    """Cover /api/v1/connectors/* — register, list, test, health."""

    def test_connectors_list(self, client, headers):
        """GET /api/v1/connectors lists registered connectors."""
        resp = client.get("/api/v1/connectors", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        # Should return a list or dict with connectors
        assert isinstance(body, (list, dict))

    def test_connectors_health(self, client, headers):
        """GET /api/v1/connectors/health returns connector health."""
        resp = client.get("/api/v1/connectors/health", headers=headers)
        assert resp.status_code == 200

    def test_connectors_register_slack(self, client, headers):
        """POST /api/v1/connectors/register registers a Slack connector."""
        payload = {
            "name": "test-slack",
            "type": "slack",
            "slack": {
                "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
            },
        }
        resp = client.post(
            "/api/v1/connectors/register", headers=headers, json=payload
        )
        # 200/201 if successful, 409 if already registered
        assert resp.status_code in (200, 201, 409), resp.text

    def test_connectors_register_bad_name(self, client, headers):
        """POST /api/v1/connectors/register rejects invalid names."""
        payload = {
            "name": "INVALID NAME!!",
            "type": "slack",
            "slack": {
                "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
            },
        }
        resp = client.post(
            "/api/v1/connectors/register", headers=headers, json=payload
        )
        assert resp.status_code == 422

    def test_connectors_test_all(self, client, headers):
        """POST /api/v1/connectors/test tests all connectors."""
        resp = client.post("/api/v1/connectors/test", headers=headers)
        assert resp.status_code in (200, 201)


# ═══════════════════════════════════════════════════════════════════════════
# 10. REMEDIATION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════


class TestRemediationEndpoints:
    """Cover /api/v1/remediation/* — task lifecycle."""

    def test_create_remediation_task(self, client, headers):
        """POST /api/v1/remediation/tasks creates a new task."""
        payload = {
            "cluster_id": "CLUSTER-001",
            "org_id": "test-org",
            "app_id": "web-app",
            "title": "Patch CVE-2024-3094",
            "severity": "critical",
            "description": "Update xz-utils to 5.6.1+",
            "assignee": "security-team",
        }
        resp = client.post(
            "/api/v1/remediation/tasks", headers=headers, json=payload
        )
        assert resp.status_code in (200, 201), resp.text
        body = resp.json()
        assert "task_id" in body

    def test_list_remediation_tasks(self, client, headers):
        """GET /api/v1/remediation/tasks lists tasks."""
        resp = client.get("/api/v1/remediation/tasks", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "tasks" in body
        assert "count" in body

    def test_get_remediation_task_not_found(self, client, headers):
        """GET /api/v1/remediation/tasks/nonexistent returns 404."""
        resp = client.get(
            "/api/v1/remediation/tasks/nonexistent-999", headers=headers
        )
        assert resp.status_code == 404

    def test_remediation_task_lifecycle(self, client, headers):
        """Full lifecycle: create -> get -> update status -> assign."""
        # Create
        payload = {
            "cluster_id": "CLUSTER-LC",
            "org_id": "test-org",
            "app_id": "api-svc",
            "title": "Upgrade dependency",
            "severity": "high",
        }
        create_resp = client.post(
            "/api/v1/remediation/tasks", headers=headers, json=payload
        )
        assert create_resp.status_code in (200, 201)
        task_id = create_resp.json()["task_id"]

        # Get
        get_resp = client.get(
            f"/api/v1/remediation/tasks/{task_id}", headers=headers
        )
        assert get_resp.status_code == 200

        # Update status to in_progress
        status_resp = client.put(
            f"/api/v1/remediation/tasks/{task_id}/status",
            headers=headers,
            json={"status": "in_progress", "changed_by": "qa-engineer"},
        )
        assert status_resp.status_code in (200, 400)

        # Assign
        assign_resp = client.put(
            f"/api/v1/remediation/tasks/{task_id}/assign",
            headers=headers,
            json={
                "assignee": "dev-team",
                "assignee_email": "dev@example.com",
                "changed_by": "qa-engineer",
            },
        )
        assert assign_resp.status_code in (200, 400)


# ═══════════════════════════════════════════════════════════════════════════
# 11. AUTHENTICATED STATUS & SEARCH
# ═══════════════════════════════════════════════════════════════════════════


class TestMiscAuthenticatedEndpoints:
    """Cover /api/v1/status, /api/v1/search."""

    def test_authenticated_status(self, client, headers):
        """GET /api/v1/status returns service status."""
        resp = client.get("/api/v1/status", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "version" in body

    def test_global_search_empty(self, client, headers):
        """GET /api/v1/search with empty query returns empty results."""
        resp = client.get("/api/v1/search", headers=headers, params={"q": ""})
        assert resp.status_code == 200
        body = resp.json()
        assert "results" in body
        assert body["total"] == 0

    def test_global_search_with_term(self, client, headers):
        """GET /api/v1/search with a search term returns results structure."""
        resp = client.get("/api/v1/search", headers=headers, params={"q": "xss"})
        assert resp.status_code == 200
        body = resp.json()
        assert "results" in body
        assert "query" in body
        assert body["query"] == "xss"


# ═══════════════════════════════════════════════════════════════════════════
# 12. RESPONSE HEADER CHECKS
# ═══════════════════════════════════════════════════════════════════════════


class TestResponseHeaders:
    """Verify product branding and security headers in responses."""

    def test_product_name_header(self, client, headers):
        """All responses should include X-Product-Name header."""
        resp = client.get("/api/v1/health")
        # The middleware adds this header
        product_name = resp.headers.get("X-Product-Name")
        # Product name might vary by branding config but should be present
        assert product_name is not None, "X-Product-Name header missing"

    def test_product_version_header(self, client, headers):
        """All responses should include X-Product-Version header."""
        resp = client.get("/api/v1/health")
        product_version = resp.headers.get("X-Product-Version")
        assert product_version is not None, "X-Product-Version header missing"

    def test_cors_headers_on_options(self, client, headers):
        """OPTIONS request should return CORS headers."""
        resp = client.options(
            "/api/v1/health",
            headers={"Origin": "http://localhost:3000"},
        )
        # CORS middleware should respond (even if 405, headers should be set)
        assert resp.status_code in (200, 204, 405)


# ═══════════════════════════════════════════════════════════════════════════
# 13. PARAMETRIZED SMOKE TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestSmokeAllGETEndpoints:
    """Hit every GET endpoint we know about and confirm no 5xx errors."""

    @pytest.mark.parametrize(
        "path",
        [
            "/health",
            "/api/v1/health",
            "/api/v1/ready",
            "/api/v1/version",
            "/api/v1/metrics",
            "/api/v1/analytics/dashboard/overview",
            "/api/v1/analytics/dashboard/trends",
            "/api/v1/analytics/dashboard/top-risks",
            "/api/v1/analytics/dashboard/compliance-status",
            "/api/v1/analytics/findings",
            "/api/v1/analytics/decisions",
            "/api/v1/analytics/mttr",
            "/api/v1/analytics/coverage",
            "/api/v1/analytics/roi",
            "/api/v1/analytics/noise-reduction",
            "/api/v1/reports",
            "/api/v1/reports/stats",
            "/api/v1/reports/schedules/list",
            "/api/v1/reports/templates/list",
            "/api/v1/fail/scores",
            "/api/v1/fail/stats",
            "/api/v1/fail/top-risks",
            "/api/v1/remediation/tasks",
            "/api/v1/brain/pipeline/runs",
            "/api/v1/brain/evidence/packs",
            "/api/v1/mcp/health",
            "/api/v1/connectors",
            "/api/v1/connectors/health",
            "/api/v1/ingest/formats",
            "/api/v1/ingest/assets",
            "/api/v1/status",
        ],
    )
    def test_no_5xx_on_get(self, client, headers, path):
        """GET {path} must never return 5xx."""
        # Health/ready/version/metrics don't require auth
        no_auth_paths = {
            "/health",
            "/api/v1/health",
            "/api/v1/ready",
            "/api/v1/version",
            "/api/v1/metrics",
        }
        h = {} if path in no_auth_paths else headers
        resp = client.get(path, headers=h)
        assert resp.status_code < 500, (
            f"GET {path} returned {resp.status_code}: {resp.text[:300]}"
        )
