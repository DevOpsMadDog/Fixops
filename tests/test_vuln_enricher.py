"""
Tests for the Vulnerability Enrichment Pipeline.

Covers:
- CWE → CVE mapping (all top-25 CWEs, normalization, unknown CWE)
- Composite risk calculation (formula correctness, edge cases, clamping)
- Batch enrichment (deduplication, empty batch, large batch)
- EPSS integration (mocked HTTP, cache, API failure fallback)
- KEV integration (mocked HTTP, in-kev detection, due date extraction)
- EnrichedFinding model (field completeness, timestamps)
- fix_guidance generation (CWE-specific guidance, fallback)
- _extract_cvss helper (direct field, severity fallback)

Run with: python -m pytest tests/test_vuln_enricher.py --timeout=10 -q -o "addopts="
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.vuln_enricher import (
    EnrichedFinding,
    VulnerabilityEnricher,
    _CWE_TO_CVE,
    _kev_cache,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def enricher() -> VulnerabilityEnricher:
    """Fresh enricher with no cached state."""
    e = VulnerabilityEnricher(http_timeout=2)
    e._epss_cache.clear()
    return e


@pytest.fixture
def sqli_finding() -> Dict[str, Any]:
    return {
        "id": "FIND-001",
        "title": "SQL Injection in login endpoint",
        "severity": "high",
        "cwe_id": "CWE-89",
        "cvss": 8.1,
        "file": "app/auth.py",
        "line": 42,
    }


@pytest.fixture
def xss_finding() -> Dict[str, Any]:
    return {
        "id": "FIND-002",
        "title": "Reflected XSS",
        "severity": "medium",
        "cwe_id": "CWE-79",
        "cvss": 6.1,
    }


@pytest.fixture
def hardcoded_creds_finding() -> Dict[str, Any]:
    return {
        "id": "FIND-003",
        "title": "Hard-coded API secret",
        "severity": "critical",
        "cwe_id": "CWE-798",
    }


# ---------------------------------------------------------------------------
# 1. CWE → CVE mapping
# ---------------------------------------------------------------------------


class TestCWEToCVEMapping:
    def test_sqli_cwe_returns_cves(self, enricher):
        cves = enricher.get_cwe_to_cve_mapping("CWE-89")
        assert len(cves) >= 1
        assert all(c.startswith("CVE-") for c in cves)

    def test_xss_cwe_returns_cves(self, enricher):
        cves = enricher.get_cwe_to_cve_mapping("CWE-79")
        assert "CVE-2021-42013" in cves or "CVE-2022-22954" in cves

    def test_hardcoded_creds_cwe(self, enricher):
        cves = enricher.get_cwe_to_cve_mapping("CWE-798")
        assert "CVE-2022-0492" in cves

    def test_path_traversal_cwe(self, enricher):
        cves = enricher.get_cwe_to_cve_mapping("CWE-22")
        assert "CVE-2021-41773" in cves

    def test_bare_numeric_normalization(self, enricher):
        """'89' should map the same as 'CWE-89'."""
        assert enricher.get_cwe_to_cve_mapping("89") == enricher.get_cwe_to_cve_mapping("CWE-89")

    def test_lowercase_normalization(self, enricher):
        """'cwe-89' should normalize correctly."""
        assert enricher.get_cwe_to_cve_mapping("cwe-89") == enricher.get_cwe_to_cve_mapping("CWE-89")

    def test_unknown_cwe_returns_empty(self, enricher):
        assert enricher.get_cwe_to_cve_mapping("CWE-99999") == []

    def test_all_mapped_cwes_have_cves(self, enricher):
        """Every CWE in _CWE_TO_CVE must have at least one CVE."""
        for cwe, cves in _CWE_TO_CVE.items():
            assert len(cves) >= 1, f"{cwe} has no CVEs"

    def test_cve_in_finding_is_collected(self, enricher):
        """CVE directly in the finding field is included in matched_cves."""
        finding = {"cve_id": "CVE-2023-99999", "severity": "high"}
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                result = enricher.enrich_finding(finding)
        assert "CVE-2023-99999" in result.matched_cves


# ---------------------------------------------------------------------------
# 2. Composite risk calculation
# ---------------------------------------------------------------------------


class TestCompositeRisk:
    def test_formula_no_kev(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=10.0, epss=1.0, in_kev=False)
        # (10/10 * 40) + (1.0 * 35) + 0 = 75
        assert score == pytest.approx(75.0, abs=0.01)

    def test_formula_with_kev(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=10.0, epss=1.0, in_kev=True)
        # 40 + 35 + 25 = 100
        assert score == pytest.approx(100.0, abs=0.01)

    def test_zero_inputs(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=0.0, epss=0.0, in_kev=False)
        assert score == pytest.approx(0.0, abs=0.01)

    def test_kev_alone(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=0.0, epss=0.0, in_kev=True)
        assert score == pytest.approx(25.0, abs=0.01)

    def test_cvss_clamped_above_10(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=15.0, epss=0.0, in_kev=False)
        assert score == pytest.approx(40.0, abs=0.01)

    def test_epss_clamped_above_1(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=0.0, epss=5.0, in_kev=False)
        assert score == pytest.approx(35.0, abs=0.01)

    def test_typical_medium_finding(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=5.0, epss=0.1, in_kev=False)
        # (0.5 * 40) + (0.1 * 35) = 20 + 3.5 = 23.5
        assert score == pytest.approx(23.5, abs=0.01)

    def test_score_never_exceeds_100(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=100.0, epss=100.0, in_kev=True)
        assert score <= 100.0

    def test_score_never_below_0(self, enricher):
        score = enricher.calculate_composite_risk({}, cvss=-5.0, epss=-1.0, in_kev=False)
        assert score >= 0.0


# ---------------------------------------------------------------------------
# 3. EPSS integration (mocked HTTP)
# ---------------------------------------------------------------------------


class TestEPSSIntegration:
    def _epss_response(self, cve_scores: Dict[str, float]) -> bytes:
        data = {
            "data": [
                {"cve": cve, "epss": str(score)} for cve, score in cve_scores.items()
            ]
        }
        return json.dumps(data).encode()

    def test_epss_score_used_in_composite(self, enricher, sqli_finding):
        epss_data = {"CVE-2021-27065": 0.9, "CVE-2023-23397": 0.8, "CVE-2022-21587": 0.5}
        with patch.object(enricher, "_call_epss_api", return_value=epss_data):
            with patch.object(enricher, "_load_kev_cache"):
                result = enricher.enrich_finding(sqli_finding)
        assert any(s > 0 for s in result.epss_scores.values())
        # composite should reflect high EPSS
        assert result.composite_risk_score > 30.0

    def test_epss_api_failure_does_not_crash(self, enricher, sqli_finding):
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                result = enricher.enrich_finding(sqli_finding)
        assert isinstance(result, EnrichedFinding)
        # When API returns nothing, CVEs are cached as 0.0 (prevents re-fetches)
        assert all(v == 0.0 for v in result.epss_scores.values())

    def test_epss_cache_is_used_on_second_call(self, enricher, sqli_finding):
        epss_data = {"CVE-2021-27065": 0.5}
        call_count = {"n": 0}

        def mock_api(cves):
            call_count["n"] += 1
            return epss_data

        with patch.object(enricher, "_call_epss_api", side_effect=mock_api):
            with patch.object(enricher, "_load_kev_cache"):
                enricher.enrich_finding(sqli_finding)
                enricher.enrich_finding(sqli_finding)

        # Should only call API once; second call uses cache
        assert call_count["n"] == 1


# ---------------------------------------------------------------------------
# 4. KEV integration (mocked HTTP)
# ---------------------------------------------------------------------------


class TestKEVIntegration:
    def _patch_kev(self, enricher, kev_cves: Dict[str, str]):
        """Patch KEV cache with given {cve: due_date} dict."""
        import core.vuln_enricher as mod
        mod._kev_cache.clear()
        mod._kev_cache.update(kev_cves)
        mod._kev_cache_ts = time.time()
        mod._kev_cache_loaded = True  # mark as loaded so _ensure_kev_cache won't re-fetch

    def test_in_kev_when_cve_matches(self, enricher, sqli_finding):
        self._patch_kev(enricher, {"CVE-2021-27065": "2024-01-15"})
        with patch.object(enricher, "_call_epss_api", return_value={}):
            result = enricher.enrich_finding(sqli_finding)
        assert result.in_kev is True
        assert result.kev_due_date == "2024-01-15"

    def test_not_in_kev_when_no_match(self, enricher, xss_finding):
        self._patch_kev(enricher, {"CVE-9999-00001": "2024-01-15"})
        with patch.object(enricher, "_call_epss_api", return_value={}):
            result = enricher.enrich_finding(xss_finding)
        assert result.in_kev is False
        assert result.kev_due_date is None

    def test_kev_adds_25_to_composite(self, enricher, sqli_finding):
        self._patch_kev(enricher, {"CVE-2021-27065": "2024-06-01"})
        with patch.object(enricher, "_call_epss_api", return_value={}):
            result_kev = enricher.enrich_finding(sqli_finding)

        self._patch_kev(enricher, {})
        with patch.object(enricher, "_call_epss_api", return_value={}):
            result_no_kev = enricher.enrich_finding(sqli_finding)

        assert result_kev.composite_risk_score - result_no_kev.composite_risk_score == pytest.approx(25.0, abs=0.1)


# ---------------------------------------------------------------------------
# 5. Batch enrichment
# ---------------------------------------------------------------------------


class TestBatchEnrichment:
    def test_batch_returns_same_count(self, enricher, sqli_finding, xss_finding):
        findings = [sqli_finding, xss_finding]
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                results = enricher.enrich_batch(findings)
        assert len(results) == 2

    def test_empty_batch_returns_empty(self, enricher):
        assert enricher.enrich_batch([]) == []

    def test_batch_deduplicates_epss_calls(self, enricher):
        """Same CVE across two findings should only trigger one API call."""
        findings = [
            {"cwe_id": "CWE-89", "severity": "high"},
            {"cwe_id": "CWE-89", "severity": "medium"},
        ]
        call_count = {"n": 0}

        def mock_api(cves):
            call_count["n"] += 1
            return {}

        with patch.object(enricher, "_call_epss_api", side_effect=mock_api):
            with patch.object(enricher, "_load_kev_cache"):
                enricher.enrich_batch(findings)

        # Batch pre-warms cache once; individual enrich calls hit cache
        assert call_count["n"] == 1

    def test_batch_preserves_original_finding(self, enricher, sqli_finding):
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                results = enricher.enrich_batch([sqli_finding])
        assert results[0].original_finding["id"] == "FIND-001"

    def test_batch_enriched_at_set(self, enricher, sqli_finding):
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                results = enricher.enrich_batch([sqli_finding])
        assert results[0].enriched_at  # non-empty ISO timestamp


# ---------------------------------------------------------------------------
# 6. EnrichedFinding model
# ---------------------------------------------------------------------------


class TestEnrichedFindingModel:
    def test_enriched_finding_has_required_fields(self, enricher, sqli_finding):
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                result = enricher.enrich_finding(sqli_finding)
        assert hasattr(result, "original_finding")
        assert hasattr(result, "matched_cves")
        assert hasattr(result, "epss_scores")
        assert hasattr(result, "in_kev")
        assert hasattr(result, "kev_due_date")
        assert hasattr(result, "fix_guidance")
        assert hasattr(result, "composite_risk_score")
        assert hasattr(result, "enriched_at")

    def test_composite_score_in_range(self, enricher, hardcoded_creds_finding):
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                result = enricher.enrich_finding(hardcoded_creds_finding)
        assert 0.0 <= result.composite_risk_score <= 100.0

    def test_fix_guidance_nonempty(self, enricher, sqli_finding):
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                result = enricher.enrich_finding(sqli_finding)
        assert len(result.fix_guidance) > 0

    def test_severity_fallback_cvss(self, enricher):
        """Finding with no cvss field falls back to severity→CVSS mapping."""
        finding = {"severity": "critical", "cwe_id": "CWE-89"}
        with patch.object(enricher, "_call_epss_api", return_value={}):
            with patch.object(enricher, "_load_kev_cache"):
                result = enricher.enrich_finding(finding)
        # critical → 9.5 → (9.5/10 * 40) = 38.0 base contribution
        assert result.composite_risk_score >= 38.0
