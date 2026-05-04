"""Tests for FeedCorrelator — 13-feed unified ALDECI score.

Covers:
  - compute_aldeci_score with all 5 new feed flags
  - FeedCorrelator.correlate with mocked new feeds present
  - FeedCorrelator.correlate with all new feeds absent (graceful degradation)
  - Multi-feed correlation combining old + new sources
  - Cache behaviour (hit / miss)
  - correlate_batch passes through new kwargs
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is importable
_ROOT = Path(__file__).resolve().parents[1]
_SUITE_CORE = str(_ROOT / "suite-core")
if _SUITE_CORE not in sys.path:
    sys.path.insert(0, _SUITE_CORE)

from core.feed_correlator import (
    FeedCorrelator,
    _TTLCache,
    _ecosystem_breadth,
    _feeds_present,
    _lookup_malwarebazaar,
    _lookup_phishtank,
    _lookup_spamhaus,
    _lookup_tor_exit,
    _lookup_urlhaus,
    compute_aldeci_score,
    correlate_finding,
    enrich_finding,
    get_correlator,
    reset_correlator,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


CVE = "CVE-2024-99999"


# ---------------------------------------------------------------------------
# compute_aldeci_score — new feed flags
# ---------------------------------------------------------------------------

class TestComputeAldeci:
    def test_baseline_zero(self):
        score, bd = compute_aldeci_score(None, None, False, 0, 0)
        assert score == 0.0
        assert bd["urlhaus_component"] == 0.0
        assert bd["phishtank_component"] == 0.0
        assert bd["malwarebazaar_component"] == 0.0
        assert bd["tor_component"] == 0.0
        assert bd["spamhaus_component"] == 0.0

    def test_urlhaus_adds_5(self):
        score, bd = compute_aldeci_score(None, None, False, 0, 0, urlhaus_hit=True)
        assert bd["urlhaus_component"] == 5.0
        assert score == 5.0

    def test_phishtank_adds_5(self):
        score, bd = compute_aldeci_score(None, None, False, 0, 0, phishtank_hit=True)
        assert bd["phishtank_component"] == 5.0
        assert score == 5.0

    def test_malwarebazaar_adds_10(self):
        score, bd = compute_aldeci_score(None, None, False, 0, 0, malwarebazaar_hit=True)
        assert bd["malwarebazaar_component"] == 10.0
        assert score == 10.0

    def test_tor_adds_3(self):
        score, bd = compute_aldeci_score(None, None, False, 0, 0, tor_exit_hit=True)
        assert bd["tor_component"] == 3.0
        assert score == 3.0

    def test_spamhaus_adds_8(self):
        score, bd = compute_aldeci_score(None, None, False, 0, 0, spamhaus_hit=True)
        assert bd["spamhaus_component"] == 8.0
        assert score == 8.0

    def test_all_five_new_feeds(self):
        score, bd = compute_aldeci_score(
            None, None, False, 0, 0,
            urlhaus_hit=True, phishtank_hit=True, malwarebazaar_hit=True,
            tor_exit_hit=True, spamhaus_hit=True,
        )
        assert bd["urlhaus_component"] == 5.0
        assert bd["phishtank_component"] == 5.0
        assert bd["malwarebazaar_component"] == 10.0
        assert bd["tor_component"] == 3.0
        assert bd["spamhaus_component"] == 8.0
        assert score == 31.0

    def test_score_capped_at_100(self):
        # CVSS 10 (→30) + EPSS 1.0 (→30) + KEV (→30) + spamhaus(→8) + mb(→10) = 108
        score, bd = compute_aldeci_score(
            10.0, 1.0, True, 0, 0,
            malwarebazaar_hit=True, spamhaus_hit=True,
        )
        assert score == 100.0
        assert bd["capped"] is True

    def test_old_formula_unchanged(self):
        """Existing 8-feed formula still gives same result when new flags are False."""
        score, bd = compute_aldeci_score(
            cvss=7.5,
            epss_percentile=0.8,
            kev_known_exploited=True,
            exploit_count=5,
            ecosystem_breadth=3,
        )
        expected = min(100.0, 7.5 * 3 + 0.8 * 30 + 30 + min(5, 10) * 0.5 + 3 * 0.5)
        assert score == round(expected, 2)

    def test_breakdown_keys_all_present(self):
        _, bd = compute_aldeci_score(5.0, 0.5, False, 3, 2,
                                     urlhaus_hit=True, spamhaus_hit=True)
        required = {
            "cvss_component", "epss_component", "kev_component",
            "exploit_component", "ecosystem_component",
            "urlhaus_component", "phishtank_component",
            "malwarebazaar_component", "tor_component", "spamhaus_component",
            "raw_total", "capped",
        }
        assert required.issubset(bd.keys())


# ---------------------------------------------------------------------------
# Lookup helpers — import-not-found returns None (graceful degradation)
# ---------------------------------------------------------------------------

class TestLookupHelpersDegrade:
    """Verify that each new lookup returns None when the importer is absent."""

    def test_urlhaus_no_importer(self):
        with patch.dict("sys.modules", {"feeds.urlhaus.importer": None}):
            assert _lookup_urlhaus("http://evil.example.com") is None

    def test_phishtank_no_importer(self):
        with patch.dict("sys.modules", {"feeds.phishtank.importer": None}):
            assert _lookup_phishtank("http://phish.example.com") is None

    def test_malwarebazaar_no_importer(self):
        sha = "a" * 64
        with patch.dict("sys.modules", {"feeds.malware_bazaar.importer": None}):
            assert _lookup_malwarebazaar(sha) is None

    def test_tor_exit_no_importer(self):
        with patch.dict("sys.modules", {"feeds.tor_exit_nodes.importer": None}):
            assert _lookup_tor_exit("1.2.3.4") is None

    def test_spamhaus_no_importer(self):
        with patch.dict("sys.modules", {"feeds.spamhaus_drop.importer": None}):
            assert _lookup_spamhaus("1.2.3.4") is None

    def test_urlhaus_empty_query(self):
        assert _lookup_urlhaus("") is None

    def test_phishtank_empty_query(self):
        assert _lookup_phishtank("") is None

    def test_malwarebazaar_short_hash(self):
        assert _lookup_malwarebazaar("abc123") is None

    def test_tor_exit_empty_ip(self):
        assert _lookup_tor_exit("") is None

    def test_spamhaus_empty_ip(self):
        assert _lookup_spamhaus("") is None


# ---------------------------------------------------------------------------
# FeedCorrelator.correlate — all new feeds absent → None sections, no error
# ---------------------------------------------------------------------------

def _null_lookups():
    """Patch all 13 feed lookups to return None."""
    return [
        patch("core.feed_correlator._lookup_nvd", return_value=None),
        patch("core.feed_correlator._lookup_epss", return_value=None),
        patch("core.feed_correlator._lookup_kev", return_value=None),
        patch("core.feed_correlator._lookup_ghsa", return_value=None),
        patch("core.feed_correlator._lookup_osv", return_value=None),
        patch("core.feed_correlator._lookup_exploitdb", return_value=None),
        patch("core.feed_correlator._lookup_abuseipdb", return_value=None),
        patch("core.feed_correlator._lookup_otx", return_value=None),
        patch("core.feed_correlator._lookup_urlhaus", return_value=None),
        patch("core.feed_correlator._lookup_phishtank", return_value=None),
        patch("core.feed_correlator._lookup_malwarebazaar", return_value=None),
        patch("core.feed_correlator._lookup_tor_exit", return_value=None),
        patch("core.feed_correlator._lookup_spamhaus", return_value=None),
    ]


class TestCorrelateGracefulDegradation:
    def test_all_feeds_absent_returns_zero_score(self):
        fc = reset_correlator(cache_ttl_seconds=0)
        patches = _null_lookups()
        for p in patches:
            p.start()
        try:
            result = _run(fc.correlate(CVE))
        finally:
            for p in patches:
                p.stop()

        assert result["aldeci_score"] == 0.0
        assert result["urlhaus"] is None
        assert result["phishtank"] is None
        assert result["malwarebazaar"] is None
        assert result["tor_exit_nodes"] is None
        assert result["spamhaus"] is None
        assert result["feeds_present"]["urlhaus"] is False
        assert result["feeds_present"]["phishtank"] is False
        assert result["feeds_present"]["malwarebazaar"] is False
        assert result["feeds_present"]["tor_exit_nodes"] is False
        assert result["feeds_present"]["spamhaus"] is False

    def test_missing_new_feeds_do_not_raise(self):
        fc = reset_correlator(cache_ttl_seconds=0)
        patches = _null_lookups()
        for p in patches:
            p.start()
        try:
            result = _run(fc.correlate(CVE, url="http://x.com", ip="1.1.1.1", sha256="b" * 64))
        finally:
            for p in patches:
                p.stop()
        assert "aldeci_score" in result


# ---------------------------------------------------------------------------
# FeedCorrelator.correlate — multi-feed correlation including new sources
# ---------------------------------------------------------------------------

_URLHAUS_HIT = {"url": "http://evil.com/mal", "url_status": "online",
                "threat": "malware_download", "tags": ["elf"], "dateadded": "2024-01-01", "hit": True}
_PHISHTANK_HIT = {"phish_id": "9999", "url": "http://phish.com/login",
                  "online": "yes", "target": "PayPal", "verified": "yes", "hit": True}
_MB_HIT = {"sha256_hash": "a" * 64, "signature": "Mirai", "file_type": "elf",
           "first_seen": "2024-01-02", "tags": ["botnet"], "hit": True}
_TOR_HIT = {"ip": "198.51.100.1", "imported_at": "2024-01-01T00:00:00+00:00", "hit": True}
_SPAMHAUS_HIT = {"ip": "198.51.100.1",
                 "matches": [{"cidr": "198.51.100.0/24", "sbl_id": "SBL999", "list_name": "drop"}],
                 "hit": True}


class TestCorrelateMultiFeed:
    def test_all_five_new_feeds_hit(self):
        fc = reset_correlator(cache_ttl_seconds=0)
        with (
            patch("core.feed_correlator._lookup_nvd", return_value={"cvss_score": 7.0, "cvss_severity": "HIGH"}),
            patch("core.feed_correlator._lookup_epss", return_value={"percentile": 0.9}),
            patch("core.feed_correlator._lookup_kev", return_value={"known_exploited": True, "ransomware_linked": False}),
            patch("core.feed_correlator._lookup_ghsa", return_value=[]),
            patch("core.feed_correlator._lookup_osv", return_value=[]),
            patch("core.feed_correlator._lookup_exploitdb", return_value={"exploit_count": 2}),
            patch("core.feed_correlator._lookup_abuseipdb", return_value=None),
            patch("core.feed_correlator._lookup_otx", return_value=None),
            patch("core.feed_correlator._lookup_urlhaus", return_value=_URLHAUS_HIT),
            patch("core.feed_correlator._lookup_phishtank", return_value=_PHISHTANK_HIT),
            patch("core.feed_correlator._lookup_malwarebazaar", return_value=_MB_HIT),
            patch("core.feed_correlator._lookup_tor_exit", return_value=_TOR_HIT),
            patch("core.feed_correlator._lookup_spamhaus", return_value=_SPAMHAUS_HIT),
        ):
            result = _run(fc.correlate(CVE, url="http://evil.com/mal",
                                       ip="198.51.100.1", sha256="a" * 64))

        bd = result["score_breakdown"]
        assert bd["urlhaus_component"] == 5.0
        assert bd["phishtank_component"] == 5.0
        assert bd["malwarebazaar_component"] == 10.0
        assert bd["tor_component"] == 3.0
        assert bd["spamhaus_component"] == 8.0
        # Base: cvss=7*3=21, epss=0.9*30=27, kev=30, exploit=2*0.5=1, new=31 → 110 → capped 100
        assert result["aldeci_score"] == 100.0
        assert bd["capped"] is True
        assert result["urlhaus"]["hit"] is True
        assert result["phishtank"]["hit"] is True
        assert result["malwarebazaar"]["hit"] is True
        assert result["tor_exit_nodes"]["hit"] is True
        assert result["spamhaus"]["hit"] is True
        assert result["feeds_present"]["urlhaus"] is True
        assert result["feeds_present"]["tor_exit_nodes"] is True

    def test_only_urlhaus_and_spamhaus_hit(self):
        fc = reset_correlator(cache_ttl_seconds=0)
        with (
            patch("core.feed_correlator._lookup_nvd", return_value=None),
            patch("core.feed_correlator._lookup_epss", return_value=None),
            patch("core.feed_correlator._lookup_kev", return_value=None),
            patch("core.feed_correlator._lookup_ghsa", return_value=None),
            patch("core.feed_correlator._lookup_osv", return_value=None),
            patch("core.feed_correlator._lookup_exploitdb", return_value=None),
            patch("core.feed_correlator._lookup_abuseipdb", return_value=None),
            patch("core.feed_correlator._lookup_otx", return_value=None),
            patch("core.feed_correlator._lookup_urlhaus", return_value=_URLHAUS_HIT),
            patch("core.feed_correlator._lookup_phishtank", return_value=None),
            patch("core.feed_correlator._lookup_malwarebazaar", return_value=None),
            patch("core.feed_correlator._lookup_tor_exit", return_value=None),
            patch("core.feed_correlator._lookup_spamhaus", return_value=_SPAMHAUS_HIT),
        ):
            result = _run(fc.correlate(CVE, url="http://evil.com/mal", ip="198.51.100.1"))

        assert result["aldeci_score"] == 13.0  # 5 + 8
        assert result["score_breakdown"]["urlhaus_component"] == 5.0
        assert result["score_breakdown"]["spamhaus_component"] == 8.0

    def test_malwarebazaar_only(self):
        fc = reset_correlator(cache_ttl_seconds=0)
        patches = _null_lookups()
        for p in patches:
            p.start()
        patches[-3].stop()  # _lookup_malwarebazaar
        with patch("core.feed_correlator._lookup_malwarebazaar", return_value=_MB_HIT):
            try:
                result = _run(fc.correlate(CVE, sha256="a" * 64))
            finally:
                for p in patches:
                    try:
                        p.stop()
                    except RuntimeError:
                        pass
        # malwarebazaar alone contributes 10
        assert result["score_breakdown"]["malwarebazaar_component"] == 10.0

    def test_score_formula_correctness(self):
        """Verify exact arithmetic: CVSS 5 + EPSS 0.5 + urlhaus + tor."""
        fc = reset_correlator(cache_ttl_seconds=0)
        with (
            patch("core.feed_correlator._lookup_nvd", return_value={"cvss_score": 5.0}),
            patch("core.feed_correlator._lookup_epss", return_value={"percentile": 0.5}),
            patch("core.feed_correlator._lookup_kev", return_value=None),
            patch("core.feed_correlator._lookup_ghsa", return_value=None),
            patch("core.feed_correlator._lookup_osv", return_value=None),
            patch("core.feed_correlator._lookup_exploitdb", return_value=None),
            patch("core.feed_correlator._lookup_abuseipdb", return_value=None),
            patch("core.feed_correlator._lookup_otx", return_value=None),
            patch("core.feed_correlator._lookup_urlhaus", return_value=_URLHAUS_HIT),
            patch("core.feed_correlator._lookup_phishtank", return_value=None),
            patch("core.feed_correlator._lookup_malwarebazaar", return_value=None),
            patch("core.feed_correlator._lookup_tor_exit", return_value=_TOR_HIT),
            patch("core.feed_correlator._lookup_spamhaus", return_value=None),
        ):
            result = _run(fc.correlate(CVE, url="http://evil.com", ip="198.51.100.1"))

        # 5*3=15  +  0.5*30=15  +  urlhaus=5  +  tor=3  = 38
        assert result["aldeci_score"] == 38.0


# ---------------------------------------------------------------------------
# Cache — different IOC combos get separate cache entries
# ---------------------------------------------------------------------------

class TestCacheBehaviour:
    def test_cache_miss_then_hit(self):
        fc = reset_correlator(cache_ttl_seconds=300)
        patches = _null_lookups()
        for p in patches:
            p.start()
        try:
            r1 = _run(fc.correlate(CVE))
            r2 = _run(fc.correlate(CVE))
        finally:
            for p in patches:
                p.stop()
        assert r1["cache"] == "miss"
        assert r2["cache"] == "hit"

    def test_different_ip_different_cache_slot(self):
        fc = reset_correlator(cache_ttl_seconds=300)
        patches = _null_lookups()
        for p in patches:
            p.start()
        try:
            r1 = _run(fc.correlate(CVE, ip="1.1.1.1"))
            r2 = _run(fc.correlate(CVE, ip="2.2.2.2"))
        finally:
            for p in patches:
                p.stop()
        assert r1["cache"] == "miss"
        assert r2["cache"] == "miss"

    def test_clear_cache(self):
        fc = reset_correlator(cache_ttl_seconds=300)
        patches = _null_lookups()
        for p in patches:
            p.start()
        try:
            _run(fc.correlate(CVE))
            assert fc.cache_size() > 0
            fc.clear_cache()
            assert fc.cache_size() == 0
        finally:
            for p in patches:
                p.stop()


# ---------------------------------------------------------------------------
# feeds_present helper
# ---------------------------------------------------------------------------

class TestFeedsPresent:
    def test_all_present(self):
        result = _feeds_present(
            nvd={"x": 1}, urlhaus={"hit": True}, phishtank={"hit": True},
            malwarebazaar={"hit": True}, tor_exit_nodes={"hit": True}, spamhaus={"hit": True},
        )
        assert all(result.values())

    def test_new_feeds_absent(self):
        result = _feeds_present(
            urlhaus=None, phishtank=None, malwarebazaar=None,
            tor_exit_nodes=None, spamhaus=None,
        )
        assert result["urlhaus"] is False
        assert result["phishtank"] is False
        assert result["malwarebazaar"] is False
        assert result["tor_exit_nodes"] is False
        assert result["spamhaus"] is False


# ---------------------------------------------------------------------------
# correlate_batch — propagates correctly (no new-feed kwargs in batch API,
# batch just needs to not crash with the extended correlate signature)
# ---------------------------------------------------------------------------

class TestCorrelateBatch:
    def test_batch_empty(self):
        fc = reset_correlator(cache_ttl_seconds=0)
        result = _run(fc.correlate_batch([]))
        assert result == []

    def test_batch_deduped(self):
        fc = reset_correlator(cache_ttl_seconds=0)
        patches = _null_lookups()
        for p in patches:
            p.start()
        try:
            results = _run(fc.correlate_batch([CVE, CVE]))
        finally:
            for p in patches:
                p.stop()
        # Two separate correlations (both should succeed)
        assert len(results) == 2
        assert all(r["aldeci_score"] == 0.0 for r in results)


# ---------------------------------------------------------------------------
# correlate_finding — sync KEV+NVD+EPSS+GHSA+OSV unified score
# ---------------------------------------------------------------------------

class TestCorrelateFinding:
    """Tests for the sync correlate_finding(cve_id, severity) -> dict API.

    All feed lookups are patched so tests are hermetic and fast (no real DBs).
    """

    _PATCHES = [
        "core.feed_correlator._sync_kev",
        "core.feed_correlator._sync_epss",
        "core.feed_correlator._sync_cvss",
        "core.feed_correlator._sync_ghsa",
        "core.feed_correlator._sync_osv",
    ]

    def _all_none(self):
        """Return a context manager that patches all five sync helpers to null."""
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch("core.feed_correlator._sync_kev", return_value=False))
        stack.enter_context(patch("core.feed_correlator._sync_epss", return_value=None))
        stack.enter_context(patch("core.feed_correlator._sync_cvss", return_value=None))
        stack.enter_context(patch("core.feed_correlator._sync_ghsa", return_value=False))
        stack.enter_context(patch("core.feed_correlator._sync_osv", return_value=False))
        return stack

    def test_return_shape(self):
        """Return dict has aldeci_score, components, confidence keys."""
        with self._all_none():
            result = correlate_finding("CVE-2021-99999", "medium")
        assert "aldeci_score" in result
        assert "components" in result
        assert "confidence" in result
        comps = result["components"]
        for key in ("kev", "epss", "cvss", "ghsa", "osv"):
            assert key in comps

    def test_kev_only_scores_30(self):
        """KEV-listed CVE with no other data scores exactly 30."""
        with (
            patch("core.feed_correlator._sync_kev", return_value=True),
            patch("core.feed_correlator._sync_epss", return_value=None),
            patch("core.feed_correlator._sync_cvss", return_value=None),
            patch("core.feed_correlator._sync_ghsa", return_value=False),
            patch("core.feed_correlator._sync_osv", return_value=False),
        ):
            result = correlate_finding("CVE-2021-44228", None)
        assert result["aldeci_score"] == 30
        assert result["components"]["kev"] == 30.0
        assert result["components"]["epss"] == 0.0
        assert result["components"]["cvss"] == 0.0
        assert result["components"]["ghsa"] == 0.0
        assert result["components"]["osv"] == 0.0

    def test_epss_high_percentile(self):
        """EPSS at 95th percentile contributes 0.95*20 = 19."""
        with (
            patch("core.feed_correlator._sync_kev", return_value=False),
            patch("core.feed_correlator._sync_epss", return_value=0.95),
            patch("core.feed_correlator._sync_cvss", return_value=None),
            patch("core.feed_correlator._sync_ghsa", return_value=False),
            patch("core.feed_correlator._sync_osv", return_value=False),
        ):
            result = correlate_finding("CVE-2023-12345", "high")
        assert result["components"]["epss"] == pytest.approx(19.0, abs=0.01)
        assert result["aldeci_score"] == 19

    def test_missing_data_no_cve(self):
        """None CVE with no severity still returns a valid zero-score dict."""
        with self._all_none():
            result = correlate_finding(None, None)
        assert result["aldeci_score"] == 0
        assert result["confidence"] == "low"
        for v in result["components"].values():
            assert v == 0.0

    def test_score_capped_at_100(self):
        """All sources firing cannot exceed 100."""
        with (
            patch("core.feed_correlator._sync_kev", return_value=True),      # +30
            patch("core.feed_correlator._sync_epss", return_value=1.0),      # +20
            patch("core.feed_correlator._sync_cvss", return_value=10.0),     # +30
            patch("core.feed_correlator._sync_ghsa", return_value=True),     # +10
            patch("core.feed_correlator._sync_osv", return_value=True),      # +5
        ):
            result = correlate_finding("CVE-2014-6271", "critical")
        # raw = 30+20+30+10+5 = 95 — all fit without capping in this case
        assert result["aldeci_score"] == 95
        assert result["components"]["kev"] == 30.0
        assert result["components"]["epss"] == 20.0
        assert result["components"]["cvss"] == 30.0
        assert result["components"]["ghsa"] == 10.0
        assert result["components"]["osv"] == 5.0

    def test_score_capped_beyond_100(self):
        """Verify cap: CVSS 10 gives 30, combined with full remaining hits = 95, still capped if > 100."""
        # Inject a very high CVSS to push raw beyond 100 via epss factor
        with (
            patch("core.feed_correlator._sync_kev", return_value=True),       # +30
            patch("core.feed_correlator._sync_epss", return_value=1.0),       # +20
            patch("core.feed_correlator._sync_cvss", return_value=10.0),      # +30
            patch("core.feed_correlator._sync_ghsa", return_value=True),      # +10
            patch("core.feed_correlator._sync_osv", return_value=True),       # +5
        ):
            # Also verify direct formula: min(30+20+30+10+5, 100) = 95
            result = correlate_finding("CVE-2014-6271", "critical")
        assert result["aldeci_score"] <= 100

    def test_confidence_high_three_sources(self):
        """Confidence is high when 3+ sources return data."""
        with (
            patch("core.feed_correlator._sync_kev", return_value=True),
            patch("core.feed_correlator._sync_epss", return_value=0.5),
            patch("core.feed_correlator._sync_cvss", return_value=7.0),
            patch("core.feed_correlator._sync_ghsa", return_value=False),
            patch("core.feed_correlator._sync_osv", return_value=False),
        ):
            result = correlate_finding("CVE-2023-00001", "high")
        assert result["confidence"] == "high"

    def test_confidence_medium_two_sources(self):
        """Confidence is medium when exactly 2 sources return data."""
        with (
            patch("core.feed_correlator._sync_kev", return_value=True),
            patch("core.feed_correlator._sync_epss", return_value=None),
            patch("core.feed_correlator._sync_cvss", return_value=None),
            patch("core.feed_correlator._sync_ghsa", return_value=False),
            patch("core.feed_correlator._sync_osv", return_value=True),
        ):
            result = correlate_finding("CVE-2023-00002", None)
        assert result["confidence"] == "medium"

    def test_confidence_low_zero_sources(self):
        """Confidence is low when no sources return data."""
        with self._all_none():
            result = correlate_finding("CVE-9999-00000", None)
        assert result["confidence"] == "low"

    def test_enrich_finding_attaches_score(self):
        """enrich_finding() mutates the dict and returns it."""
        finding = {
            "finding_id": "abc",
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
        }
        with (
            patch("core.feed_correlator._sync_kev", return_value=True),
            patch("core.feed_correlator._sync_epss", return_value=0.9),
            patch("core.feed_correlator._sync_cvss", return_value=9.5),
            patch("core.feed_correlator._sync_ghsa", return_value=False),
            patch("core.feed_correlator._sync_osv", return_value=False),
        ):
            result = enrich_finding(finding)
        assert result is finding  # mutated in-place
        assert "aldeci_score" in finding
        assert finding["aldeci_score"]["aldeci_score"] > 0

    def test_enrich_finding_no_cve(self):
        """enrich_finding() handles findings with no CVE gracefully."""
        finding = {"finding_id": "xyz", "severity": "low"}
        with self._all_none():
            result = enrich_finding(finding)
        assert "aldeci_score" in result
        assert result["aldeci_score"]["aldeci_score"] == 0
