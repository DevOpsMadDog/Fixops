"""Tests for CVE enrichment service — uses built-in data only, no network calls."""
import json
import sys
import os
import tempfile
import unittest.mock
from datetime import datetime, timedelta
from io import BytesIO
import pytest

sys.path.insert(0, "suite-core")

from core.cve_enrichment import CVEEnrichmentService, BUILT_IN_CVES, _KEV_CACHE_TTL_HOURS, _SHODAN_CACHE_TTL_DAYS


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


# ---------------------------------------------------------------------------
# CISA KEV — is_kev() public method
# ---------------------------------------------------------------------------

_KEV_PAYLOAD = json.dumps({
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "dateAdded": "2021-12-10",
        },
        {
            "cveID": "CVE-2022-0778",
            "dueDate": "2022-04-01",
            "knownRansomwareCampaignUse": "Unknown",
            "dateAdded": "2022-03-25",
        },
    ]
}).encode()


def _make_kev_response():
    """Return a mock urlopen context manager yielding KEV payload."""
    mock_resp = unittest.mock.MagicMock()
    mock_resp.read.return_value = _KEV_PAYLOAD
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
    return mock_resp


@pytest.fixture
def svc_no_patch(tmp_path):
    """CVEEnrichmentService backed by a temp DB — network NOT patched (tests control it)."""
    return CVEEnrichmentService(
        db_path=str(tmp_path / "test_kev.db"),
        cache_ttl_hours=24,
    )


def test_is_kev_true_for_log4shell(svc_no_patch):
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_kev_response()):
        result = svc_no_patch.is_kev("CVE-2021-44228")
    assert result["is_kev"] is True


def test_is_kev_false_for_unknown(svc_no_patch):
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_kev_response()):
        result = svc_no_patch.is_kev("CVE-9999-99999")
    assert result["is_kev"] is False


def test_is_kev_returns_due_date(svc_no_patch):
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_kev_response()):
        result = svc_no_patch.is_kev("CVE-2021-44228")
    assert result["kev_due_date"] == "2021-12-24"


def test_is_kev_returns_ransomware_use(svc_no_patch):
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_kev_response()):
        result = svc_no_patch.is_kev("CVE-2021-44228")
    assert result["kev_ransomware_use"] == "Known"


def test_kev_cache_ttl_is_six_hours():
    assert _KEV_CACHE_TTL_HOURS == 6


def test_kev_catalog_cached_after_first_fetch(svc_no_patch):
    """Second call to is_kev must NOT hit the network again (catalog cached in SQLite)."""
    call_count = 0

    def counting_urlopen(req, timeout=None):
        nonlocal call_count
        call_count += 1
        return _make_kev_response()

    with unittest.mock.patch("urllib.request.urlopen", side_effect=counting_urlopen):
        svc_no_patch.is_kev("CVE-2021-44228")
        svc_no_patch.is_kev("CVE-2022-0778")

    assert call_count == 1, f"Expected 1 network call but got {call_count}"


# ---------------------------------------------------------------------------
# Shodan InternetDB — enrich_ip()
# ---------------------------------------------------------------------------

_SHODAN_PAYLOAD = json.dumps({
    "ip": "8.8.8.8",
    "ports": [53, 443],
    "hostnames": ["dns.google"],
    "cpes": [],
    "tags": ["anycast"],
    "vulns": [],
}).encode()


def _make_shodan_response():
    mock_resp = unittest.mock.MagicMock()
    mock_resp.read.return_value = _SHODAN_PAYLOAD
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
    return mock_resp


def test_enrich_ip_returns_dict(svc_no_patch):
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_shodan_response()):
        with unittest.mock.patch("time.sleep"):
            result = svc_no_patch.enrich_ip("8.8.8.8")
    assert isinstance(result, dict)


def test_enrich_ip_has_ports(svc_no_patch):
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_shodan_response()):
        with unittest.mock.patch("time.sleep"):
            result = svc_no_patch.enrich_ip("8.8.8.8")
    assert result["ports"] == [53, 443]


def test_enrich_ip_has_hostnames(svc_no_patch):
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_shodan_response()):
        with unittest.mock.patch("time.sleep"):
            result = svc_no_patch.enrich_ip("8.8.8.8")
    assert "dns.google" in result["hostnames"]


def test_shodan_cache_ttl_is_five_days():
    assert _SHODAN_CACHE_TTL_DAYS == 5


def test_enrich_ip_cached_on_second_call(svc_no_patch):
    """Second enrich_ip call must return from cache without a network request."""
    call_count = 0

    def counting_urlopen(req, timeout=None):
        nonlocal call_count
        call_count += 1
        return _make_shodan_response()

    with unittest.mock.patch("urllib.request.urlopen", side_effect=counting_urlopen):
        with unittest.mock.patch("time.sleep"):
            svc_no_patch.enrich_ip("8.8.8.8")
            result2 = svc_no_patch.enrich_ip("8.8.8.8")

    assert call_count == 1, f"Expected 1 network call but got {call_count}"
    assert result2["source"] == "cache"


# ---------------------------------------------------------------------------
# EPSS — epss_date in enrich_cve() network result
# ---------------------------------------------------------------------------

_NVD_PAYLOAD = json.dumps({
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 10.0,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    }
                }]
            },
            "weaknesses": [],
        }
    }]
}).encode()

_EPSS_PAYLOAD = json.dumps({
    "data": [{"cve": "CVE-2021-44228", "epss": "0.943580", "percentile": "0.999610", "date": "2026-04-14"}]
}).encode()

_KEV_EMPTY = json.dumps({"vulnerabilities": []}).encode()


def _urlopen_router(req, timeout=None):
    """Route mock urlopen calls to correct payload by URL."""
    url = req.full_url if hasattr(req, "full_url") else str(req)
    mock_resp = unittest.mock.MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
    if "nvd.nist.gov" in url:
        mock_resp.read.return_value = _NVD_PAYLOAD
    elif "first.org" in url:
        mock_resp.read.return_value = _EPSS_PAYLOAD
    elif "cisa.gov" in url:
        mock_resp.read.return_value = _KEV_EMPTY
    else:
        mock_resp.read.return_value = b"{}"
    return mock_resp


def test_enrich_cve_network_includes_epss_date(tmp_path):
    svc = CVEEnrichmentService(db_path=str(tmp_path / "epss_test.db"), cache_ttl_hours=24)
    with unittest.mock.patch("urllib.request.urlopen", side_effect=_urlopen_router):
        result = svc.enrich_cve("CVE-2021-44228", use_cache=False)
    assert result.get("epss_date") == "2026-04-14"


def test_enrich_cve_network_includes_epss_score(tmp_path):
    svc = CVEEnrichmentService(db_path=str(tmp_path / "epss_score_test.db"), cache_ttl_hours=24)
    with unittest.mock.patch("urllib.request.urlopen", side_effect=_urlopen_router):
        result = svc.enrich_cve("CVE-2021-44228", use_cache=False)
    assert abs(result["epss_score"] - 0.94358) < 0.001


# ---------------------------------------------------------------------------
# CIRCL CVE lookup — GET /api/v1/cve/circl/{cve_id}
# ---------------------------------------------------------------------------

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from fastapi.testclient import TestClient
from fastapi import FastAPI

# Build a minimal app with just the CVE enrichment router
_app = FastAPI()
from apps.api.cve_enrichment_router import router as _cve_router
_app.include_router(_cve_router)
_client = TestClient(_app, raise_server_exceptions=False)


_CIRCL_PAYLOAD = json.dumps({
    "id": "CVE-2021-44228",
    "summary": "Apache Log4j2 JNDI RCE vulnerability (Log4Shell).",
    "cvss": 10.0,
    "cvss-vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "cwe": "CWE-917",
    "Published": "2021-12-10T00:00:00",
    "Modified": "2022-01-20T00:00:00",
    "vulnerable_product": ["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"],
    "references": ["https://logging.apache.org/log4j/2.x/security.html"],
    "capec": [],
}).encode()


def _make_circl_response(payload: bytes = _CIRCL_PAYLOAD):
    mock_resp = unittest.mock.MagicMock()
    mock_resp.read.return_value = payload
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
    return mock_resp


def test_circl_lookup_status_200():
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_circl_response()):
        resp = _client.get("/api/v1/cve/circl/CVE-2021-44228")
    assert resp.status_code == 200


def test_circl_lookup_source_is_circl():
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_circl_response()):
        data = _client.get("/api/v1/cve/circl/CVE-2021-44228").json()
    assert data["source"] == "circl"


def test_circl_lookup_cve_id_normalised():
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_circl_response()):
        data = _client.get("/api/v1/cve/circl/cve-2021-44228").json()
    assert data["cve_id"] == "CVE-2021-44228"


def test_circl_lookup_cvss_score():
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_circl_response()):
        data = _client.get("/api/v1/cve/circl/CVE-2021-44228").json()
    assert data["cvss_score"] == 10.0
    assert data["cvss_severity"] == "critical"


def test_circl_lookup_description():
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_circl_response()):
        data = _client.get("/api/v1/cve/circl/CVE-2021-44228").json()
    assert "Log4Shell" in data["description"]


def test_circl_lookup_404_on_empty_response():
    empty_resp = _make_circl_response(b"null")
    with unittest.mock.patch("urllib.request.urlopen", return_value=empty_resp):
        resp = _client.get("/api/v1/cve/circl/CVE-9999-99999")
    assert resp.status_code == 404


def test_circl_lookup_502_on_network_error():
    with unittest.mock.patch(
        "urllib.request.urlopen",
        side_effect=Exception("connection refused"),
    ):
        resp = _client.get("/api/v1/cve/circl/CVE-2021-44228")
    assert resp.status_code == 502


def test_circl_lookup_has_fetched_at():
    with unittest.mock.patch("urllib.request.urlopen", return_value=_make_circl_response()):
        data = _client.get("/api/v1/cve/circl/CVE-2021-44228").json()
    assert "fetched_at" in data and data["fetched_at"]
