"""Assert that the CSPM posture endpoint never returns a fabricated perfect score.

Founder mandate: NO fake data.  The previous monkey-patch block returned
overall_score=100.0 / total_findings=0 on every unconfigured tenant, silently
deceiving customers into believing their cloud posture was perfect.

This test suite verifies:
1. CSPMNotConfiguredError is raised (not swallowed) by engine methods that
   require a live cloud connector.
2. The /posture and /scan endpoints return HTTP 503 (not 200 with fake data).
3. The 503 body carries status="not_configured" and configured=False — honest,
   not a fabricated perfect score.
4. overall_score=100.0 combined with total_findings=0 is never returned from
   an unconfigured engine (the specific dangerous fabrication pattern).
5. The IaC scanner methods (scan_terraform, scan_cloudformation) remain
   unaffected — they are real and must still work.
6. The allowlist CRUD endpoints remain operational without a connector.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make suite-core importable
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-attack"))


# ---------------------------------------------------------------------------
# 1. Engine-level: CSPMNotConfiguredError is raised, not swallowed
# ---------------------------------------------------------------------------

class TestEngineNotConfigured:
    """CSPMEngine methods that require a cloud connector must raise
    CSPMNotConfiguredError — never return fabricated data."""

    def setup_method(self):
        from core.cspm_engine import CSPMEngine, CSPMNotConfiguredError
        self.engine = CSPMEngine()
        self.exc = CSPMNotConfiguredError

    def test_get_posture_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.get_posture("test-org")

    def test_run_scan_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.run_scan("test-org")

    def test_list_findings_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.list_findings("test-org")

    def test_list_resources_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.list_resources("test-org")

    def test_get_benchmark_status_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.get_benchmark_status("test-org")

    def test_list_drift_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.list_drift("test-org")

    def test_save_baseline_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.save_baseline("test-org")

    def test_get_remediation_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.get_remediation("some-finding-id")

    def test_get_compliance_map_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.get_compliance_map()

    def test_get_finding_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.get_finding("some-finding-id")

    def test_suppress_finding_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.suppress_finding("some-finding-id", "reason")

    def test_resolve_finding_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.resolve_finding("some-finding-id")

    def test_list_scans_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.list_scans("test-org")

    def test_get_resource_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.get_resource("some-resource-id")

    def test_delete_resource_raises_not_configured(self):
        with pytest.raises(self.exc):
            self.engine.delete_resource("some-resource-id")

    def test_no_fabricated_perfect_score(self):
        """The specific dangerous fabrication: overall_score=100.0 + total_findings=0
        must NEVER be returned from an unconfigured engine."""
        try:
            result = self.engine.get_posture("empty-tenant")
            # If it didn't raise, it must not be a fabricated perfect posture
            assert not (
                getattr(result, "overall_score", None) == 100.0
                and getattr(result, "total_findings", None) == 0
                and getattr(result, "total_resources", None) == 0
            ), (
                "get_posture returned overall_score=100.0 / total_findings=0 on an "
                "unconfigured tenant — this is a fabricated perfect score, not real data."
            )
        except self.exc:
            pass  # Correct behaviour: raises rather than fabricates


# ---------------------------------------------------------------------------
# 2. Router-level: HTTP 503 with honest not_configured body
# ---------------------------------------------------------------------------

class TestRouterNotConfigured:
    """The CSPM router must translate CSPMNotConfiguredError into HTTP 503
    with an honest not_configured body — never 200 with fake data."""

    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        # Import the real router (via the symlink target)
        sys.path.insert(0, str(Path(__file__).parent.parent / "suite-attack" / "api"))
        from cspm_router import router
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_posture_returns_503_not_200(self):
        resp = self.client.get("/api/v1/cspm/posture")
        assert resp.status_code == 503, (
            f"Expected 503 not_configured, got {resp.status_code}: {resp.text}"
        )

    def test_posture_body_not_fabricated(self):
        resp = self.client.get("/api/v1/cspm/posture")
        assert resp.status_code == 503
        body = resp.json()
        detail = body.get("detail", {})
        assert detail.get("status") == "not_configured"
        assert detail.get("configured") is False
        # Specifically assert the fabricated values are absent
        assert detail.get("overall_score") != 100.0, "overall_score=100.0 in 503 body"
        assert detail.get("total_findings") != 0 or "overall_score" not in detail

    def test_scan_returns_503_not_200(self):
        resp = self.client.post("/api/v1/cspm/scan", json={"org_id": "test"})
        assert resp.status_code == 503, (
            f"Expected 503 not_configured, got {resp.status_code}: {resp.text}"
        )

    def test_scan_body_not_fabricated(self):
        resp = self.client.post("/api/v1/cspm/scan", json={"org_id": "test"})
        assert resp.status_code == 503
        detail = resp.json().get("detail", {})
        assert detail.get("status") == "not_configured"
        assert detail.get("configured") is False

    def test_findings_returns_503(self):
        resp = self.client.get("/api/v1/cspm/findings")
        assert resp.status_code == 503

    def test_resources_returns_503(self):
        resp = self.client.get("/api/v1/cspm/resources")
        assert resp.status_code == 503

    def test_benchmarks_returns_503(self):
        resp = self.client.get("/api/v1/cspm/benchmarks")
        assert resp.status_code == 503

    def test_drift_returns_503(self):
        resp = self.client.get("/api/v1/cspm/drift")
        assert resp.status_code == 503

    def test_compliance_map_returns_503(self):
        resp = self.client.get("/api/v1/cspm/compliance-map")
        assert resp.status_code == 503

    def test_health_does_not_return_fabricated_healthy(self):
        """Health must not claim 'healthy' with fake resource counts."""
        resp = self.client.get("/api/v1/cspm/health")
        assert resp.status_code == 200  # health always responds
        body = resp.json()
        # Must be not_configured or degraded — never 'healthy' with fake data
        assert body.get("status") in ("not_configured", "degraded"), (
            f"Health returned unexpected status '{body.get('status')}': {body}"
        )
        # Specifically: must not claim healthy with fake resource counts
        assert not (
            body.get("status") == "healthy"
            and body.get("resources_tracked") == 0
        ), "Health returned healthy with 0 resources — likely fabricated"


# ---------------------------------------------------------------------------
# 3. IaC scanner unaffected — real methods still work
# ---------------------------------------------------------------------------

class TestIaCScannerStillWorks:
    """scan_terraform and scan_cloudformation are real and must remain
    unaffected by the not-configured fix."""

    def setup_method(self):
        from core.cspm_engine import CSPMEngine
        self.engine = CSPMEngine()

    def test_scan_terraform_clean_template(self):
        hcl = '''
resource "aws_cloudtrail" "main" {
  name                          = "main"
  s3_bucket_name                = "my-bucket"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
'''
        result = self.engine.scan_terraform(hcl)
        # A real scan result — score may be 100 here because the template is clean,
        # but this is a real computed score from real input, not fabricated.
        assert result is not None
        assert hasattr(result, "compliance_score")
        assert 0.0 <= result.compliance_score <= 100.0
        assert result.scan_id.startswith("cspm-")

    def test_scan_terraform_public_s3_finds_finding(self):
        hcl = 'resource "aws_s3_bucket_acl" "bad" { acl = "public-read" }\n'
        result = self.engine.scan_terraform(hcl)
        assert result.total_findings >= 1
        assert result.compliance_score < 100.0

    def test_scan_cloudformation_empty_template(self):
        cf = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}'
        result = self.engine.scan_cloudformation(cf)
        assert result is not None
        assert result.total_findings == 0

    def test_scan_cloudformation_public_s3(self):
        cf = '''{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"AccessControl": "PublicRead"}
                }
            }
        }'''
        result = self.engine.scan_cloudformation(cf)
        assert result.total_findings >= 1


# ---------------------------------------------------------------------------
# 4. Allowlist CRUD works without a connector
# ---------------------------------------------------------------------------

class TestAllowlistNoConnectorNeeded:
    """Allowlist endpoints must work without a cloud connector configured."""

    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        sys.path.insert(0, str(Path(__file__).parent.parent / "suite-attack" / "api"))
        from cspm_router import router
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_add_allowlist_entry_succeeds(self):
        resp = self.client.post("/api/v1/cspm/allowlist", json={
            "rule_id": "CSPM-AWS-001",
            "reason": "Accepted risk — internal bucket only",
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["rule_id"] == "CSPM-AWS-001"
        assert body["id"].startswith("allow-")

    def test_list_allowlist_entries(self):
        resp = self.client.get("/api/v1/cspm/allowlist")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
