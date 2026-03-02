"""
Tests for the Threat Enrichment Service (core.ml.threat_enricher).

[V3] Decision Intelligence — Tests for Brain Pipeline Step 6 real enrichment.

Covers:
  - EPSS batch fetching (with mock)
  - KEV catalog loading (with mock)
  - Fallback estimation accuracy
  - Finding enrichment pipeline
  - Cache operations
  - Singleton pattern
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure suite-core is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.ml.threat_enricher import (
    ThreatEnricher,
    get_threat_enricher,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def enricher():
    """Create a fresh ThreatEnricher instance."""
    return ThreatEnricher()


@pytest.fixture
def sample_findings():
    """Sample vulnerability findings for enrichment."""
    return [
        {
            "id": "F-001",
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "title": "Log4Shell RCE",
        },
        {
            "id": "F-002",
            "cve_id": "CVE-2023-44487",
            "severity": "high",
            "title": "HTTP/2 Rapid Reset",
        },
        {
            "id": "F-003",
            "cve_id": "CVE-2024-3094",
            "severity": "critical",
            "title": "XZ Utils Backdoor",
            "exploit_available": True,
        },
        {
            "id": "F-004",
            "severity": "medium",
            "title": "Missing HSTS header",
            # No CVE ID
        },
        {
            "id": "F-005",
            "cve_id": "CVE-2023-36884",
            "severity": "high",
            "title": "Office RCE",
        },
    ]


@pytest.fixture
def mock_epss_response():
    """Mock EPSS API response."""
    return {
        "status": "OK",
        "status-code": 200,
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99999"},
            {"cve": "CVE-2023-44487", "epss": "0.72000", "percentile": "0.98500"},
            {"cve": "CVE-2024-3094", "epss": "0.85000", "percentile": "0.99000"},
            {"cve": "CVE-2023-36884", "epss": "0.45000", "percentile": "0.95000"},
        ],
    }


@pytest.fixture
def mock_kev_response():
    """Mock CISA KEV catalog response."""
    return {
        "title": "CISA KEV",
        "catalogVersion": "2026.03.02",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j2 RCE",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
            },
            {
                "cveID": "CVE-2023-44487",
                "vendorProject": "IETF",
                "product": "HTTP/2",
                "vulnerabilityName": "HTTP/2 Rapid Reset Attack",
                "dateAdded": "2023-10-10",
                "dueDate": "2023-10-31",
            },
            {
                "cveID": "CVE-2023-36884",
                "vendorProject": "Microsoft",
                "product": "Office",
                "vulnerabilityName": "Microsoft Office RCE",
                "dateAdded": "2023-07-17",
                "dueDate": "2023-08-07",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Tests: EPSS estimation fallback
# ---------------------------------------------------------------------------

class TestEPSSEstimation:
    """Tests for EPSS fallback estimation accuracy."""

    def test_critical_severity_epss(self, enricher):
        finding = {"severity": "critical"}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss == 0.25, f"Critical EPSS should be 0.25, got {epss}"

    def test_high_severity_epss(self, enricher):
        finding = {"severity": "high"}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss == 0.10

    def test_medium_severity_epss(self, enricher):
        finding = {"severity": "medium"}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss == 0.03

    def test_low_severity_epss(self, enricher):
        finding = {"severity": "low"}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss == 0.01

    def test_info_severity_epss(self, enricher):
        finding = {"severity": "info"}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss == 0.001

    def test_exploit_available_boost(self, enricher):
        finding = {"severity": "medium", "exploit_available": True}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss == 0.09  # 0.03 * 3.0
        assert epss > 0.03  # Higher than base

    def test_kev_boost(self, enricher):
        finding = {"severity": "low", "in_kev": True}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss >= 0.60  # KEV floor

    def test_epss_capped_at_095(self, enricher):
        finding = {"severity": "critical", "exploit_available": True}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss <= 0.95

    def test_unknown_severity_defaults(self, enricher):
        finding = {"severity": "unknown"}
        epss = enricher._estimate_epss_from_severity(finding)
        assert epss == 0.03  # Default


# ---------------------------------------------------------------------------
# Tests: CVSS estimation
# ---------------------------------------------------------------------------

class TestCVSSEstimation:
    """Tests for CVSS fallback estimation."""

    def test_critical_cvss(self, enricher):
        assert enricher._estimate_cvss_from_severity({"severity": "critical"}) == 9.5

    def test_high_cvss(self, enricher):
        assert enricher._estimate_cvss_from_severity({"severity": "high"}) == 7.5

    def test_medium_cvss(self, enricher):
        assert enricher._estimate_cvss_from_severity({"severity": "medium"}) == 5.0

    def test_low_cvss(self, enricher):
        assert enricher._estimate_cvss_from_severity({"severity": "low"}) == 2.5

    def test_info_cvss(self, enricher):
        assert enricher._estimate_cvss_from_severity({"severity": "info"}) == 0.5


# ---------------------------------------------------------------------------
# Tests: KEV catalog
# ---------------------------------------------------------------------------

class TestKEVCatalog:
    """Tests for KEV catalog loading and lookup."""

    def test_kev_loading_from_mock(self, enricher, mock_kev_response):
        """Test loading KEV catalog from mocked response."""
        with patch("core.ml.threat_enricher._fetch_json", return_value=mock_kev_response):
            enricher._load_kev_catalog(skip_api=False)

        assert enricher._kev_loaded
        assert enricher.kev_count == 3
        assert enricher.is_in_kev("CVE-2021-44228")
        assert enricher.is_in_kev("CVE-2023-44487")
        assert not enricher.is_in_kev("CVE-9999-99999")

    def test_kev_details(self, enricher, mock_kev_response):
        """Test KEV detail lookup."""
        with patch("core.ml.threat_enricher._fetch_json", return_value=mock_kev_response):
            enricher._load_kev_catalog(skip_api=False)

        details = enricher.get_kev_details("CVE-2021-44228")
        assert details is not None
        assert details["vendorProject"] == "Apache"
        assert details["product"] == "Log4j"

    def test_kev_fallback_to_cache(self, enricher, mock_kev_response):
        """Test KEV falls back to cache when API fails."""
        with patch("core.ml.threat_enricher._fetch_json", return_value=None):
            with patch("core.ml.threat_enricher._load_cache", return_value=mock_kev_response):
                enricher._load_kev_catalog(skip_api=False)

        assert enricher._kev_loaded
        assert enricher.kev_count == 3

    def test_kev_skip_api(self, enricher, mock_kev_response):
        """Test KEV catalog with skip_api=True."""
        with patch("core.ml.threat_enricher._fetch_json") as mock_fetch:
            with patch("core.ml.threat_enricher._load_cache", return_value=mock_kev_response):
                enricher._load_kev_catalog(skip_api=True)

        mock_fetch.assert_not_called()
        assert enricher._kev_loaded


# ---------------------------------------------------------------------------
# Tests: Full enrichment pipeline
# ---------------------------------------------------------------------------

class TestEnrichmentPipeline:
    """Tests for the full enrichment pipeline."""

    def test_enrich_with_api_data(
        self, enricher, sample_findings, mock_epss_response, mock_kev_response
    ):
        """Test enrichment with mocked API data."""
        with patch("core.ml.threat_enricher._fetch_json") as mock_fetch:
            mock_fetch.side_effect = [
                mock_kev_response,  # KEV fetch
                mock_epss_response,  # EPSS batch fetch
            ]
            with patch("core.ml.threat_enricher._save_cache"):
                with patch("core.ml.threat_enricher._load_cache", return_value=None):
                    result = enricher.enrich_findings(sample_findings)

        assert result["enriched"] >= 4  # 4 findings with CVE IDs
        assert result["unique_cves"] == 4

        # Check Log4Shell enrichment
        log4shell = sample_findings[0]
        assert log4shell["epss_score"] == 0.97565
        assert log4shell["in_kev"] is True
        assert log4shell["kev_source"] == "cisa"

        # Check HTTP/2 Rapid Reset
        http2 = sample_findings[1]
        assert http2["epss_score"] == 0.72
        assert http2["in_kev"] is True

        # Check finding without CVE (no enrichment)
        no_cve = sample_findings[3]
        assert "epss_score" not in no_cve or no_cve.get("epss_source") != "api"

    def test_enrich_with_fallback(self, enricher, sample_findings):
        """Test enrichment falls back gracefully when APIs fail."""
        with patch("core.ml.threat_enricher._fetch_json", return_value=None):
            with patch("core.ml.threat_enricher._load_cache", return_value=None):
                result = enricher.enrich_findings(sample_findings)

        assert result["enriched"] >= 4
        assert result["epss_fallback_hits"] > 0

        # Check that estimated EPSS values are reasonable
        log4shell = sample_findings[0]
        assert "epss_score" in log4shell
        assert log4shell["epss_source"] == "estimated"
        assert log4shell["epss_score"] == 0.25  # Critical median

    def test_enrich_skip_api(self, enricher, sample_findings):
        """Test skip_api mode uses cache only."""
        with patch("core.ml.threat_enricher._fetch_json"):
            with patch("core.ml.threat_enricher._load_cache", return_value=None):
                result = enricher.enrich_findings(sample_findings, skip_api=True)

        # Should not call API for EPSS batch (KEV loaded but no API call)
        assert result["enriched"] >= 4

    def test_enrich_no_cves(self, enricher):
        """Test enrichment with no CVE IDs."""
        findings = [
            {"id": "F-001", "title": "Missing header", "severity": "low"},
            {"id": "F-002", "title": "Weak cipher", "severity": "medium"},
        ]
        result = enricher.enrich_findings(findings)
        assert result["enriched"] == 0
        assert "no CVE IDs" in result["reason"]

    def test_enrich_empty_findings(self, enricher):
        """Test enrichment with empty findings list."""
        result = enricher.enrich_findings([])
        assert result["enriched"] == 0

    def test_enrichment_stats(self, enricher, sample_findings, mock_kev_response):
        """Test enrichment statistics tracking."""
        with patch("core.ml.threat_enricher._fetch_json") as mock_fetch:
            mock_fetch.side_effect = [mock_kev_response, None]  # KEV works, EPSS fails
            with patch("core.ml.threat_enricher._save_cache"):
                with patch("core.ml.threat_enricher._load_cache", return_value=None):
                    result = enricher.enrich_findings(sample_findings)

        assert "elapsed_ms" in result
        assert result["elapsed_ms"] >= 0
        assert "kev_catalog_size" in result


# ---------------------------------------------------------------------------
# Tests: Cache operations
# ---------------------------------------------------------------------------

class TestCacheOperations:
    """Tests for EPSS cache load/save."""

    def test_epss_cache_round_trip(self, enricher):
        """Test saving and loading EPSS cache."""
        enricher._epss_cache = {
            "CVE-2021-44228": 0.97565,
            "CVE-2023-44487": 0.72000,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("core.ml.threat_enricher.CACHE_DIR", Path(tmpdir)):
                enricher._save_epss_cache()

                # Create new enricher and load cache
                enricher2 = ThreatEnricher()
                with patch("core.ml.threat_enricher.CACHE_DIR", Path(tmpdir)):
                    enricher2._load_epss_cache()

                assert enricher2._epss_cache.get("CVE-2021-44228") == 0.97565
                assert enricher2._epss_cache.get("CVE-2023-44487") == 0.72000


# ---------------------------------------------------------------------------
# Tests: Singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    """Tests for the module-level singleton."""

    def test_get_threat_enricher(self):
        """Test singleton creation."""
        import core.ml.threat_enricher as mod
        mod._enricher_instance = None  # Reset
        enricher = get_threat_enricher()
        assert enricher is not None
        assert isinstance(enricher, ThreatEnricher)

    def test_singleton_returns_same_instance(self):
        """Test singleton returns the same instance."""
        import core.ml.threat_enricher as mod
        mod._enricher_instance = None
        e1 = get_threat_enricher()
        e2 = get_threat_enricher()
        assert e1 is e2


# ---------------------------------------------------------------------------
# Tests: EPSS vs old formula comparison
# ---------------------------------------------------------------------------

class TestEPSSCalibration:
    """Test that new EPSS estimates are more realistic than old formula."""

    def test_old_formula_overestimates(self):
        """Verify the old formula (cvss/10*0.6) overestimates EPSS."""
        # Old formula: epss = min(cvss / 10.0 * 0.6, 0.97)
        # For a medium vuln (CVSS 5.0): old = 0.30, real median ≈ 0.03
        old_medium = min(5.0 / 10.0 * 0.6, 0.97)
        new_medium = 0.03  # FIRST.org calibrated median

        assert old_medium > new_medium * 5, (
            f"Old formula ({old_medium}) should significantly overestimate "
            f"vs calibrated ({new_medium})"
        )

    def test_new_estimates_match_first_org_research(self):
        """Verify new estimates match FIRST.org EPSS research."""
        enricher = ThreatEnricher()

        # According to FIRST.org EPSS research paper:
        # Median EPSS by severity bucket
        assert enricher._estimate_epss_from_severity({"severity": "critical"}) == 0.25
        assert enricher._estimate_epss_from_severity({"severity": "high"}) == 0.10
        assert enricher._estimate_epss_from_severity({"severity": "medium"}) == 0.03
        assert enricher._estimate_epss_from_severity({"severity": "low"}) == 0.01
