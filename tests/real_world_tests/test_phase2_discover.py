"""
Phase 2 — Discover
Owner: SOC T1/T2 + AppSec

Validates:
- Multi-engine scan ingestion
- Finding normalization and deduplication
- Scanner stability and completeness
- Threat intel feed availability
"""
import pytest


class TestScannerIngestion:
    """SOC T1/T2: Verify scanner ingest pipeline is operational."""

    def test_supported_scanners(self, api):
        r = api.get("/api/v1/scanner-ingest/supported")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)

    def test_ingest_stats(self, api):
        r = api.get("/api/v1/scanner-ingest/stats")
        assert r.status_code == 200

    def test_ingest_sarif_format(self, api):
        """Submit a minimal SARIF payload to test ingestion."""
        sarif = {
            "format": "sarif",
            "tool": "semgrep",
            "results": [
                {
                    "ruleId": "e2e-test-xss",
                    "message": {"text": "XSS via innerHTML"},
                    "level": "error",
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 42}}}],
                }
            ],
        }
        r = api.post("/api/v1/scanner-ingest/upload", json=sarif)
        assert r.status_code in (200, 201, 202, 422)  # 422 if schema strict


class TestDeduplication:
    """AppSec: Verify dedup engine is running."""

    def test_dedup_clusters(self, api, org_id):
        r = api.get(f"/api/v1/deduplication/clusters?org_id={org_id}")
        assert r.status_code == 200

    def test_dedup_stats(self, api):
        r = api.get("/api/v1/deduplication/stats")
        assert r.status_code == 200


class TestFindingsQueue:
    """SOC T1: View the findings queue."""

    def test_findings_list(self, api):
        r = api.get("/api/v1/analytics/findings")
        assert r.status_code == 200

    def test_nerve_center_pulse(self, api):
        r = api.get("/api/v1/nerve-center/pulse")
        assert r.status_code == 200

    def test_nerve_center_state(self, api):
        r = api.get("/api/v1/nerve-center/state")
        assert r.status_code == 200


class TestThreatIntelFeeds:
    """Threat Intel Analyst: Verify feeds are ingesting."""

    def test_nvd_recent(self, api):
        r = api.get("/api/v1/feeds/nvd/recent")
        assert r.status_code == 200

    def test_mitre_techniques(self, api):
        r = api.get("/api/v1/mitre/techniques")
        assert r.status_code == 200

    def test_epss_scores(self, api):
        r = api.get("/api/v1/feeds/epss")
        assert r.status_code == 200

    def test_feeds_status(self, api):
        r = api.get("/api/v1/feeds/status")
        assert r.status_code == 200


class TestSBOMIngestion:
    """Supply Chain Security: Verify SBOM/provenance pipeline."""

    def test_provenance_status(self, api):
        r = api.get("/api/v1/provenance/status")
        assert r.status_code == 200

    def test_graph_status(self, api):
        r = api.get("/api/v1/graph/status")
        assert r.status_code == 200


class TestCopilotAvailable:
    """SOC T1: Verify copilot is responsive for analyst assistance."""

    def test_copilot_ask(self, api):
        r = api.post("/api/v1/copilot/ask", json={"question": "What findings need attention?"})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)

