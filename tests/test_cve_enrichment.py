"""Tests for CVE enrichment service — uses built-in data only, no network calls."""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, "suite-core")

from core.cve_enrichment import CVEEnrichmentService, BUILT_IN_CVES


@pytest.fixture
def svc(tmp_path, monkeypatch):
    """CVEEnrichmentService backed by a temp DB so tests are isolated.

    Network calls are patched out so tests run offline and fast.
    """
    instance = CVEEnrichmentService(
        db_path=str(tmp_path / "test_cve.db"),
        cache_ttl_hours=24,
    )
    # Disable network fetches — tests must rely on built-in data only
    monkeypatch.setattr(instance, "_fetch_from_network", lambda cve_id: None)
    return instance


# ---------------------------------------------------------------------------
# Basic enrichment
# ---------------------------------------------------------------------------


def test_enrich_cve_returns_dict(svc):
    result = svc.enrich_cve("CVE-2021-44228")
    assert isinstance(result, dict)


def test_enrich_log4shell_cvss_score(svc):
    result = svc.enrich_cve("CVE-2021-44228")
    assert result["cvss_score"] == 10.0


def test_enrich_log4shell_is_kev(svc):
    result = svc.enrich_cve("CVE-2021-44228")
    assert result["is_kev"] is True


def test_enrich_log4shell_kev_due_date(svc):
    result = svc.enrich_cve("CVE-2021-44228")
    assert result["kev_due_date"] == "2021-12-24"


def test_enrich_log4shell_description_present(svc):
    result = svc.enrich_cve("CVE-2021-44228")
    assert result["description"]


def test_enrich_openssl_cvss_score(svc):
    result = svc.enrich_cve("CVE-2022-0778")
    assert result["cvss_score"] == 7.5


def test_enrich_proxylogon_cvss_score(svc):
    result = svc.enrich_cve("CVE-2021-26855")
    assert result["cvss_score"] == 9.8


def test_enrich_unknown_cve_returns_dict(svc):
    """Unknown CVE must not crash — returns a dict with source indicator."""
    result = svc.enrich_cve("CVE-9999-99999")
    assert isinstance(result, dict)
    assert "cve_id" in result


def test_enrich_unknown_cve_has_source(svc):
    result = svc.enrich_cve("CVE-9999-99999")
    assert result.get("source") in ("builtin", "network", "cache")


def test_enrich_cve_source_field_present(svc):
    result = svc.enrich_cve("CVE-2021-44228")
    assert "source" in result


def test_enrich_cve_enriched_at_present(svc):
    result = svc.enrich_cve("CVE-2021-44228")
    assert "enriched_at" in result and result["enriched_at"]


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def test_severity_critical(svc):
    assert svc.get_severity(10.0) == "critical"


def test_severity_critical_lower_bound(svc):
    assert svc.get_severity(9.0) == "critical"


def test_severity_high(svc):
    assert svc.get_severity(7.5) == "high"


def test_severity_high_lower_bound(svc):
    assert svc.get_severity(7.0) == "high"


def test_severity_medium(svc):
    assert svc.get_severity(5.0) == "medium"


def test_severity_medium_lower_bound(svc):
    assert svc.get_severity(4.0) == "medium"


def test_severity_low(svc):
    assert svc.get_severity(2.0) == "low"


def test_severity_none(svc):
    assert svc.get_severity(0.0) == "none"


def test_enrich_log4shell_severity_is_critical(svc):
    result = svc.enrich_cve("CVE-2021-44228")
    assert result["cvss_severity"] == "critical"


# ---------------------------------------------------------------------------
# Batch enrichment
# ---------------------------------------------------------------------------


def test_enrich_batch_two_cves(svc):
    results = svc.enrich_batch(["CVE-2021-44228", "CVE-2022-0778"])
    assert len(results) == 2


def test_enrich_batch_empty_list(svc):
    results = svc.enrich_batch([])
    assert results == []


def test_enrich_batch_returns_list_of_dicts(svc):
    results = svc.enrich_batch(["CVE-2021-44228"])
    assert isinstance(results, list)
    assert isinstance(results[0], dict)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def test_search_min_cvss_filters_critical(svc):
    # Populate cache first
    svc.enrich_cve("CVE-2021-44228")
    svc.enrich_cve("CVE-2022-0778")
    results = svc.search_cves(min_cvss=9.0)
    for r in results:
        assert r["cvss_score"] >= 9.0


def test_search_is_kev_filters_correctly(svc):
    svc.enrich_cve("CVE-2021-44228")
    svc.enrich_cve("CVE-2022-0778")
    results = svc.search_cves(is_kev=True)
    for r in results:
        assert r["is_kev"] is True


def test_search_returns_list(svc):
    results = svc.search_cves()
    assert isinstance(results, list)


def test_search_keyword_match(svc):
    svc.enrich_cve("CVE-2021-44228")
    results = svc.search_cves(keyword="Log4j")
    # May match description
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# Cache operations
# ---------------------------------------------------------------------------


def test_get_cache_stats_returns_dict(svc):
    stats = svc.get_cache_stats()
    assert isinstance(stats, dict)


def test_get_cache_stats_has_numeric_cached_cves(svc):
    stats = svc.get_cache_stats()
    assert isinstance(stats["cached_cves"], int)


def test_get_cache_stats_has_hit_rate(svc):
    stats = svc.get_cache_stats()
    assert "cache_hit_rate" in stats
    assert isinstance(stats["cache_hit_rate"], float)


def test_invalidate_cache_returns_int(svc):
    svc.enrich_cve("CVE-2021-44228")
    count = svc.invalidate_cache()
    assert isinstance(count, int)
    assert count >= 1


def test_invalidate_specific_cve(svc):
    svc.enrich_cve("CVE-2021-44228")
    count = svc.invalidate_cache("CVE-2021-44228")
    assert isinstance(count, int)
    assert count == 1


def test_invalidate_nonexistent_cve(svc):
    count = svc.invalidate_cache("CVE-0000-00000")
    assert count == 0


# ---------------------------------------------------------------------------
# Top EPSS
# ---------------------------------------------------------------------------


def test_get_top_epss_returns_list(svc):
    svc.enrich_cve("CVE-2021-44228")
    result = svc.get_top_epss()
    assert isinstance(result, list)


def test_get_top_epss_ordered_descending(svc):
    svc.enrich_cve("CVE-2021-44228")
    svc.enrich_cve("CVE-2022-0778")
    result = svc.get_top_epss(limit=10)
    if len(result) >= 2:
        assert result[0]["epss_score"] >= result[1]["epss_score"]


# ---------------------------------------------------------------------------
# Cache hit
# ---------------------------------------------------------------------------


def test_cache_hit_on_second_call(svc):
    # First call populates cache
    r1 = svc.enrich_cve("CVE-2021-44228")
    # Second call should come from cache
    r2 = svc.enrich_cve("CVE-2021-44228")
    assert r2["source"] == "cache"
    assert r2["cvss_score"] == r1["cvss_score"]


def test_cache_bypass_with_use_cache_false(svc):
    svc.enrich_cve("CVE-2021-44228")
    r = svc.enrich_cve("CVE-2021-44228", use_cache=False)
    # Should re-fetch — source will be builtin or network, not cache
    assert r["source"] in ("builtin", "network")
