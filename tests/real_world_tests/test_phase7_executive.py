"""
Phase 7 — Executive Trust Review
Owner: CISO + CFO + CTO

Validates:
- Executive dashboard and KPI overview
- Compliance posture for board reporting
- Risk trends and ROI metrics
- Go/No-Go decision data availability
"""
import pytest


class TestExecutiveDashboard:
    """CISO: Verify executive-level dashboards."""

    def test_dashboard_overview(self, api):
        r = api.get("/api/v1/analytics/dashboard/overview")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)

    def test_dashboard_trends(self, api):
        r = api.get("/api/v1/analytics/dashboard/trends")
        assert r.status_code == 200

    def test_dashboard_top_risks(self, api):
        r = api.get("/api/v1/analytics/dashboard/top-risks")
        assert r.status_code == 200

    def test_compliance_status(self, api):
        r = api.get("/api/v1/analytics/dashboard/compliance-status")
        assert r.status_code == 200


class TestKPIMetrics:
    """VP Engineering: Verify KPI data for go/no-go decisions."""

    def test_analytics_summary(self, api):
        r = api.get("/api/v1/analytics/summary")
        assert r.status_code == 200

    def test_roi_metrics(self, api):
        r = api.get("/api/v1/analytics/roi")
        assert r.status_code == 200

    def test_mttr_metrics(self, api):
        r = api.get("/api/v1/analytics/mttr")
        assert r.status_code == 200

    def test_noise_reduction(self, api):
        r = api.get("/api/v1/analytics/noise-reduction")
        assert r.status_code == 200


class TestMCPToolsCatalog:
    """CTO: Verify AI-native MCP platform capabilities."""

    def test_mcp_tools(self, api):
        r = api.get("/api/v1/mcp/tools")
        assert r.status_code == 200

    def test_mcp_server_health(self, api):
        r = api.get("/api/v1/mcp-server/health")
        assert r.status_code in (200, 404)


class TestSystemConfig:
    """Platform Engineer: Verify system configuration is accessible."""

    def test_system_config(self, api):
        r = api.get("/api/v1/system/config")
        assert r.status_code == 200

    def test_system_health(self, api):
        r = api.get("/api/v1/system/health")
        assert r.status_code == 200


class TestEndToEndPipelineFlow:
    """
    Full pipeline validation: Ingest → Enrich → Decide → Fix → Evidence.
    This is the ultimate enterprise readiness test.
    """

    def test_full_pipeline_data_flow(self, api, org_id):
        """Verify all pipeline stages return data."""
        stages = [
            ("Ingest", "/api/v1/scanner-ingest/supported"),
            ("Dedup", f"/api/v1/deduplication/clusters?org_id={org_id}"),
            ("Enrich", "/api/v1/brain/stats"),
            ("Score", "/api/v1/fail/stats"),
            ("Validate", "/api/v1/mpte/stats"),
            ("Fix", "/api/v1/autofix/stats"),
            ("Evidence", "/api/v1/evidence/status"),
            ("Comply", "/api/v1/compliance-engine/gaps"),
            ("Dashboard", "/api/v1/analytics/dashboard/overview"),
        ]
        results = {}
        for stage_name, path in stages:
            r = api.get(path)
            results[stage_name] = r.status_code
            assert r.status_code == 200, f"Pipeline stage '{stage_name}' failed: HTTP {r.status_code}"

    def test_all_persona_endpoints_reachable(self, api):
        """Smoke test: every critical persona endpoint returns non-500."""
        critical_paths = [
            "/api/v1/analytics/dashboard/overview",
            "/api/v1/analytics/findings",
            "/api/v1/remediation/backlog",
            "/api/v1/compliance-engine/frameworks",
            "/api/v1/audit/logs",
            "/api/v1/evidence/status",
            "/api/v1/fail/stats",
            "/api/v1/brain/stats",
            "/api/v1/mpte/stats",
            "/api/v1/autofix/stats",
        ]
        for path in critical_paths:
            r = api.get(path)
            assert r.status_code < 500, f"{path} returned {r.status_code}"

