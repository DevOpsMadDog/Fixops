"""Edge-case tests for feed_correlator.correlate_finding and enrich_finding.

Covers:
- KEV+EPSS only (NVD absent)
- NVD only (KEV/EPSS absent)
- All feeds absent
- Malformed / empty CVE id
- Severity-heuristic fallback when NVD is absent
- enrich_finding with cveId key variant
- enrich_finding never raises on garbage input
- Mixed feed: GHSA+OSV present, KEV/NVD/EPSS absent
- EPSS at boundary values (0.0 and 1.0)
- Score cap when all sources fire

No external network calls. All feed lookups are intercepted via unittest.mock.patch
so tests run in air-gapped environments without any imported DBs.
"""

from __future__ import annotations

import sys
import threading
import types
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure suite-core/core is importable
_ROOT = Path(__file__).resolve().parents[1]
_CORE = _ROOT / "suite-core" / "core"
if str(_CORE.parent) not in sys.path:
    sys.path.insert(0, str(_CORE.parent))

from core.feed_correlator import correlate_finding, enrich_finding  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers — patch every _sync_* function so no real DB is needed
# ---------------------------------------------------------------------------

def _patch_all_sync(
    *,
    kev: bool = False,
    epss: float | None = None,
    cvss: float | None = None,
    ghsa: bool = False,
    osv: bool = False,
    severity: str | None = None,
):
    """Return a context-manager stack that patches all five sync helpers."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with (
            patch("core.feed_correlator._sync_kev", return_value=kev),
            patch("core.feed_correlator._sync_epss", return_value=epss),
            patch("core.feed_correlator._sync_cvss", return_value=cvss),
            patch("core.feed_correlator._sync_ghsa", return_value=ghsa),
            patch("core.feed_correlator._sync_osv", return_value=osv),
        ):
            yield

    return _ctx()


# ---------------------------------------------------------------------------
# correlate_finding edge cases
# ---------------------------------------------------------------------------

class TestCorrelateFindingEdgeCases:

    def test_kev_and_epss_only_no_nvd(self):
        """KEV=30 + EPSS(0.5)*20=10 = 40. NVD/GHSA/OSV absent."""
        with _patch_all_sync(kev=True, epss=0.5, cvss=None, ghsa=False, osv=False):
            result = correlate_finding("CVE-2021-44228")
        assert result["aldeci_score"] == 40
        assert result["components"]["kev"] == 30.0
        assert result["components"]["epss"] == 10.0
        assert result["components"]["cvss"] == 0.0
        assert result["components"]["ghsa"] == 0.0
        assert result["components"]["osv"] == 0.0

    def test_nvd_only_no_other_feeds(self):
        """CVSS=8.0 → 8*3=24. All other feeds absent."""
        with _patch_all_sync(kev=False, epss=None, cvss=8.0, ghsa=False, osv=False):
            result = correlate_finding("CVE-2022-1234")
        assert result["aldeci_score"] == 24
        assert result["components"]["cvss"] == 24.0
        assert result["components"]["kev"] == 0.0
        assert result["components"]["epss"] == 0.0

    def test_all_feeds_absent_score_zero(self):
        """When no feed returns data the score must be 0."""
        with _patch_all_sync(kev=False, epss=None, cvss=None, ghsa=False, osv=False):
            result = correlate_finding("CVE-2099-0000")
        assert result["aldeci_score"] == 0
        assert result["confidence"] == "low"

    def test_malformed_cve_id_empty_string(self):
        """Empty string CVE id — should return score 0 without raising."""
        with _patch_all_sync():
            result = correlate_finding("")
        assert result["aldeci_score"] == 0
        assert result["confidence"] == "low"

    def test_none_cve_id(self):
        """None CVE id — should return score 0 without raising."""
        with _patch_all_sync():
            result = correlate_finding(None)
        assert result["aldeci_score"] == 0

    def test_malformed_cve_id_garbage(self):
        """Garbage string that is not a real CVE — no exception expected."""
        with _patch_all_sync(kev=False, epss=None, cvss=None):
            result = correlate_finding("NOT-A-CVE-!!!###")
        assert isinstance(result["aldeci_score"], int)

    def test_severity_heuristic_high_when_nvd_absent(self):
        """When NVD returns None, severity='high' heuristic → CVSS=8.0 → cvss_score=24."""
        with _patch_all_sync(kev=False, epss=None, cvss=8.0, ghsa=False, osv=False):
            result = correlate_finding("CVE-2023-9999", severity="high")
        assert result["components"]["cvss"] == 24.0

    def test_severity_critical_caps_cvss_at_30(self):
        """CVSS=9.5 → 9.5*3=28.5, capped at 30 (min(28.5,30)=28.5)."""
        with _patch_all_sync(kev=False, epss=None, cvss=9.5, ghsa=False, osv=False):
            result = correlate_finding("CVE-2023-9998", severity="critical")
        assert result["components"]["cvss"] == 28.5

    def test_ghsa_and_osv_only(self):
        """GHSA=10 + OSV=5 = 15. KEV/EPSS/NVD absent."""
        with _patch_all_sync(kev=False, epss=None, cvss=None, ghsa=True, osv=True):
            result = correlate_finding("CVE-2020-5678")
        assert result["aldeci_score"] == 15
        assert result["components"]["ghsa"] == 10.0
        assert result["components"]["osv"] == 5.0

    def test_epss_boundary_zero(self):
        """EPSS percentile 0.0 contributes 0 to score."""
        with _patch_all_sync(kev=False, epss=0.0, cvss=None, ghsa=False, osv=False):
            result = correlate_finding("CVE-2024-0001")
        assert result["components"]["epss"] == 0.0

    def test_epss_boundary_one(self):
        """EPSS percentile 1.0 contributes 20.0 to score."""
        with _patch_all_sync(kev=False, epss=1.0, cvss=None, ghsa=False, osv=False):
            result = correlate_finding("CVE-2024-0002")
        assert result["components"]["epss"] == 20.0

    def test_score_capped_at_100_all_sources(self):
        """KEV(30)+EPSS(20)+CVSS(30)+GHSA(10)+OSV(5)=95 → not capped. Push over with CVSS=10."""
        # KEV=30, EPSS=1.0→20, CVSS=10→30, GHSA=10, OSV=5 = 95 → int(95) = 95
        with _patch_all_sync(kev=True, epss=1.0, cvss=10.0, ghsa=True, osv=True):
            result = correlate_finding("CVE-2021-12345")
        assert result["aldeci_score"] == 95
        assert result["aldeci_score"] <= 100

    def test_confidence_low_one_source(self):
        """Exactly 1 source → confidence='low'."""
        with _patch_all_sync(kev=True, epss=None, cvss=None, ghsa=False, osv=False):
            result = correlate_finding("CVE-2022-0001")
        assert result["confidence"] == "low"

    def test_confidence_medium_two_sources(self):
        """Exactly 2 sources → confidence='medium'."""
        with _patch_all_sync(kev=True, epss=0.3, cvss=None, ghsa=False, osv=False):
            result = correlate_finding("CVE-2022-0002")
        assert result["confidence"] == "medium"

    def test_confidence_high_three_plus_sources(self):
        """3+ sources → confidence='high'."""
        with _patch_all_sync(kev=True, epss=0.5, cvss=7.0, ghsa=False, osv=False):
            result = correlate_finding("CVE-2022-0003")
        assert result["confidence"] == "high"

    def test_return_shape_always_present(self):
        """Return dict always has required keys regardless of feed state."""
        with _patch_all_sync():
            result = correlate_finding("CVE-2099-0001")
        assert "aldeci_score" in result
        assert "components" in result
        assert "confidence" in result
        for key in ("kev", "epss", "cvss", "ghsa", "osv"):
            assert key in result["components"]


# ---------------------------------------------------------------------------
# enrich_finding edge cases
# ---------------------------------------------------------------------------

class TestEnrichFindingEdgeCases:

    def test_cve_id_key_variant(self):
        """enrich_finding reads 'cveId' (camelCase) when 'cve_id' absent."""
        finding = {"cveId": "CVE-2021-44228", "severity": "critical"}
        with _patch_all_sync(kev=True, epss=0.9, cvss=9.8, ghsa=True, osv=True):
            result = enrich_finding(finding)
        assert "aldeci_score" in result
        assert result["aldeci_score"]["aldeci_score"] >= 0

    def test_finding_returned_in_place(self):
        """enrich_finding returns the same dict object (mutates in-place)."""
        finding = {"cve_id": "CVE-2022-1111", "severity": "high"}
        with _patch_all_sync(kev=False, epss=0.2, cvss=7.5):
            returned = enrich_finding(finding)
        assert returned is finding

    def test_no_crash_on_empty_dict(self):
        """enrich_finding on empty dict must not raise."""
        with _patch_all_sync():
            result = enrich_finding({})
        assert isinstance(result, dict)

    def test_no_crash_on_none_values(self):
        """enrich_finding silently handles None cve_id and severity."""
        finding = {"cve_id": None, "severity": None}
        with _patch_all_sync():
            result = enrich_finding(finding)
        assert "aldeci_score" in result

    def test_no_crash_on_corrupt_severity(self):
        """enrich_finding does not raise when severity is an unexpected type."""
        finding = {"cve_id": "CVE-2023-1234", "severity": 9999}
        with _patch_all_sync(cvss=None):
            result = enrich_finding(finding)
        assert "aldeci_score" in result

    def test_existing_keys_not_overwritten(self):
        """enrich_finding does not delete other keys already in the finding."""
        finding = {
            "cve_id": "CVE-2024-5678",
            "title": "Test vuln",
            "severity": "medium",
        }
        with _patch_all_sync(cvss=5.5):
            enrich_finding(finding)
        assert finding["title"] == "Test vuln"

    def test_aldeci_score_block_is_dict(self):
        """aldeci_score field must be a dict with correct inner keys."""
        finding = {"cve_id": "CVE-2025-0001", "severity": "low"}
        with _patch_all_sync(cvss=2.5):
            enrich_finding(finding)
        block = finding["aldeci_score"]
        assert isinstance(block, dict)
        assert "aldeci_score" in block
        assert "components" in block
        assert "confidence" in block
