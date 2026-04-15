"""Tests for ThreatIntelAggregator — CVE/EPSS/KEV/OSV aggregation engine.

All tests use fixture data and mock HTTP calls — no real API requests made.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite paths resolve
import sys
_project_root = Path(__file__).parent.parent
sys.path.insert(0, str(_project_root / "suite-feeds"))
sys.path.insert(0, str(_project_root / "suite-core"))
sys.path.insert(0, str(_project_root))

from threat_intel_aggregator import (
    CVERecord,
    ThreatIntelAggregator,
    ThreatIntelReport,
    _init_db,
    _get_conn,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NVD_ITEM_FIXTURE: Dict[str, Any] = {
    "cve": {
        "id": "CVE-2024-99999",
        "published": "2024-03-01T10:00:00.000",
        "lastModified": "2024-03-02T12:00:00.000",
        "descriptions": [
            {"lang": "en", "value": "A critical buffer overflow vulnerability."},
            {"lang": "es", "value": "Una vulnerabilidad critica."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"},
                        ]
                    }
                ]
            }
        ],
    }
}

NVD_RESPONSE_FIXTURE: Dict[str, Any] = {
    "totalResults": 1,
    "vulnerabilities": [NVD_ITEM_FIXTURE],
}

EPSS_RESPONSE_FIXTURE: Dict[str, Any] = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2024-99999", "epss": "0.9712", "percentile": "0.9990"},
        {"cve": "CVE-2021-44228", "epss": "0.9750", "percentile": "0.9999"},
    ],
}

KEV_RESPONSE_FIXTURE: Dict[str, Any] = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "dueDate": "2021-12-24",
        },
        {
            "cveID": "CVE-2024-99999",
            "vendorProject": "Example",
            "product": "Product",
            "dueDate": "2024-04-01",
        },
    ],
}

# querybatch response: {"results": [{"vulns": [...]}, {"vulns": []}, ...]}
# Two packages return vulns; the rest return empty results.
OSV_RESPONSE_FIXTURE: Dict[str, Any] = {
    "results": [
        {"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz", "summary": "Prototype pollution"}]},
        {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "RCE via deserialization"}]},
        {"vulns": []},
    ]
}


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Return a path to a temporary SQLite DB for each test."""
    db = tmp_path / "test_threat_intel.db"
    _init_db(db)
    return db


@pytest.fixture
def aggregator(tmp_db: Path) -> ThreatIntelAggregator:
    """Return a ThreatIntelAggregator backed by a temp DB."""
    return ThreatIntelAggregator(db_path=tmp_db)


# ---------------------------------------------------------------------------
# 1. DB initialisation
# ---------------------------------------------------------------------------


def test_init_db_creates_tables(tmp_db: Path) -> None:
    """_init_db creates all required tables."""
    conn = _get_conn(tmp_db)
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    conn.close()
    assert "cve_cache" in tables
    assert "kev_cache" in tables
    assert "epss_cache" in tables
    assert "meta" in tables


# ---------------------------------------------------------------------------
# 2. NVD CVE parsing
# ---------------------------------------------------------------------------


def test_parse_nvd_item_full(aggregator: ThreatIntelAggregator) -> None:
    """_parse_nvd_item extracts all fields from a realistic NVD item."""
    record = aggregator._parse_nvd_item(NVD_ITEM_FIXTURE)
    assert record is not None
    assert record.cve_id == "CVE-2024-99999"
    assert record.severity == "CRITICAL"
    assert record.cvss_score == 9.8
    assert "buffer overflow" in record.description
    assert len(record.affected_products) == 1
    assert "example:product" in record.affected_products[0]


def test_parse_nvd_item_missing_id(aggregator: ThreatIntelAggregator) -> None:
    """_parse_nvd_item returns None when CVE ID is absent."""
    item = {"cve": {"descriptions": [], "metrics": {}}}
    assert aggregator._parse_nvd_item(item) is None


def test_parse_nvd_item_fallback_severity(aggregator: ThreatIntelAggregator) -> None:
    """_parse_nvd_item falls back to v2 metrics when v3 absent."""
    item = {
        "cve": {
            "id": "CVE-2020-11111",
            "published": "2020-01-01T00:00:00",
            "lastModified": "2020-01-02T00:00:00",
            "descriptions": [{"lang": "en", "value": "Old vuln"}],
            "metrics": {
                "cvssMetricV2": [
                    {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                ]
            },
            "configurations": [],
        }
    }
    record = aggregator._parse_nvd_item(item)
    assert record is not None
    assert record.severity == "HIGH"
    assert record.cvss_score == 7.5


def test_refresh_cve_feed_mocked(aggregator: ThreatIntelAggregator) -> None:
    """refresh_cve_feed returns CVERecord list from mocked NVD response."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = NVD_RESPONSE_FIXTURE
    mock_resp.raise_for_status = MagicMock()

    with patch.object(aggregator._session, "get", return_value=mock_resp):
        records = aggregator.refresh_cve_feed(days_back=7)

    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-99999"


def test_refresh_cve_feed_network_error(aggregator: ThreatIntelAggregator) -> None:
    """refresh_cve_feed returns empty list on network error (does not raise)."""
    from requests import RequestException

    with patch.object(aggregator._session, "get", side_effect=RequestException("timeout")):
        records = aggregator.refresh_cve_feed(days_back=7)

    assert records == []


# ---------------------------------------------------------------------------
# 3. SQLite caching
# ---------------------------------------------------------------------------


def test_cache_and_retrieve_cve(aggregator: ThreatIntelAggregator) -> None:
    """CVERecord survives a round-trip through the SQLite cache."""
    rec = CVERecord(
        cve_id="CVE-2024-11111",
        severity="HIGH",
        cvss_score=7.5,
        description="Test vuln",
        published="2024-01-01T00:00:00",
        last_modified="2024-01-02T00:00:00",
        affected_products=["cpe:2.3:a:test:lib:1.0"],
        epss_score=0.42,
        epss_percentile=0.88,
        in_kev=True,
        kev_due_date="2024-02-01",
    )
    aggregator._cache_cve(rec)
    cached = aggregator.get_cached_cves(limit=10)
    assert len(cached) == 1
    c = cached[0]
    assert c.cve_id == "CVE-2024-11111"
    assert c.severity == "HIGH"
    assert c.epss_score == pytest.approx(0.42)
    assert c.in_kev is True
    assert c.kev_due_date == "2024-02-01"


def test_get_cached_cves_empty(aggregator: ThreatIntelAggregator) -> None:
    """get_cached_cves returns empty list when cache is empty."""
    assert aggregator.get_cached_cves() == []


# ---------------------------------------------------------------------------
# 4. EPSS enrichment
# ---------------------------------------------------------------------------


def test_enrich_with_epss_mocked(aggregator: ThreatIntelAggregator) -> None:
    """enrich_with_epss fetches and returns EPSS scores from FIRST API."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = EPSS_RESPONSE_FIXTURE
    mock_resp.raise_for_status = MagicMock()

    cve_ids = ["CVE-2024-99999", "CVE-2021-44228"]
    with patch.object(aggregator._session, "get", return_value=mock_resp):
        scores = aggregator.enrich_with_epss(cve_ids)

    assert scores["CVE-2024-99999"] == pytest.approx(0.9712)
    assert scores["CVE-2021-44228"] == pytest.approx(0.9750)


def test_enrich_with_epss_empty_input(aggregator: ThreatIntelAggregator) -> None:
    """enrich_with_epss returns empty dict for empty input."""
    scores = aggregator.enrich_with_epss([])
    assert scores == {}


def test_enrich_with_epss_uses_cache(aggregator: ThreatIntelAggregator) -> None:
    """enrich_with_epss serves from cache without hitting the API again."""
    # Pre-populate cache
    conn = _get_conn(aggregator.db_path)
    with conn:
        conn.execute(
            "INSERT INTO epss_cache (cve_id, score, percentile, fetched_at) VALUES (?,?,?,?)",
            ("CVE-2022-12345", 0.15, 0.70, time.time()),
        )
    conn.close()

    with patch.object(aggregator._session, "get") as mock_get:
        scores = aggregator.enrich_with_epss(["CVE-2022-12345"])
        mock_get.assert_not_called()

    assert scores["CVE-2022-12345"] == pytest.approx(0.15)


def test_enrich_with_epss_network_error(aggregator: ThreatIntelAggregator) -> None:
    """enrich_with_epss returns partial results on network error."""
    from requests import RequestException

    with patch.object(aggregator._session, "get", side_effect=RequestException("err")):
        scores = aggregator.enrich_with_epss(["CVE-2024-99999"])

    # No crash; unknown CVE simply absent from result
    assert "CVE-2024-99999" not in scores


# ---------------------------------------------------------------------------
# 5. CISA KEV
# ---------------------------------------------------------------------------


def test_refresh_kev_mocked(aggregator: ThreatIntelAggregator) -> None:
    """refresh_kev parses KEV catalog and caches entries."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = KEV_RESPONSE_FIXTURE
    mock_resp.raise_for_status = MagicMock()

    with patch.object(aggregator._session, "get", return_value=mock_resp):
        kev_map = aggregator.refresh_kev()

    assert "CVE-2021-44228" in kev_map
    assert kev_map["CVE-2021-44228"] == "2021-12-24"
    assert "CVE-2024-99999" in kev_map


def test_check_kev_true(aggregator: ThreatIntelAggregator) -> None:
    """check_kev returns True for a CVE in the KEV catalog."""
    conn = _get_conn(aggregator.db_path)
    with conn:
        conn.execute(
            "INSERT INTO kev_cache (cve_id, due_date, fetched_at) VALUES (?,?,?)",
            ("CVE-2021-44228", "2021-12-24", time.time()),
        )
    conn.close()

    assert aggregator.check_kev("CVE-2021-44228") is True


def test_check_kev_false(aggregator: ThreatIntelAggregator) -> None:
    """check_kev returns False for a CVE not in the KEV catalog."""
    assert aggregator.check_kev("CVE-1999-00001") is False


def test_get_kev_due_date(aggregator: ThreatIntelAggregator) -> None:
    """get_kev_due_date returns the correct remediation date."""
    conn = _get_conn(aggregator.db_path)
    with conn:
        conn.execute(
            "INSERT INTO kev_cache (cve_id, due_date, fetched_at) VALUES (?,?,?)",
            ("CVE-2021-44228", "2021-12-24", time.time()),
        )
    conn.close()

    assert aggregator.get_kev_due_date("CVE-2021-44228") == "2021-12-24"
    assert aggregator.get_kev_due_date("CVE-9999-00000") is None


def test_refresh_kev_network_fallback(aggregator: ThreatIntelAggregator) -> None:
    """refresh_kev falls back to cache on network failure."""
    from requests import RequestException

    # Seed cache
    conn = _get_conn(aggregator.db_path)
    with conn:
        conn.execute(
            "INSERT INTO kev_cache (cve_id, due_date, fetched_at) VALUES (?,?,?)",
            ("CVE-2021-44228", "2021-12-24", time.time()),
        )
    conn.close()

    with patch.object(aggregator._session, "get", side_effect=RequestException("down")):
        kev_map = aggregator.refresh_kev()

    assert "CVE-2021-44228" in kev_map


# ---------------------------------------------------------------------------
# 6. OSV feed
# ---------------------------------------------------------------------------


def test_fetch_osv_vulns_mocked(aggregator: ThreatIntelAggregator) -> None:
    """fetch_osv_vulns returns vuln list for specified ecosystems."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = OSV_RESPONSE_FIXTURE
    mock_resp.raise_for_status = MagicMock()

    with patch.object(aggregator._session, "post", return_value=mock_resp):
        vulns = aggregator.fetch_osv_vulns(ecosystems=["PyPI"])

    assert len(vulns) == 2
    assert vulns[0]["id"] == "GHSA-xxxx-yyyy-zzzz"


# ---------------------------------------------------------------------------
# 7. OTX file-cache fallback
# ---------------------------------------------------------------------------


def test_load_otx_pulses_file_exists(aggregator: ThreatIntelAggregator, tmp_path: Path) -> None:
    """load_otx_pulses reads pulse list from otx_sample.json."""
    sample = [{"id": "abc123", "name": "Log4Shell campaign"}]
    sample_file = tmp_path / "otx_sample.json"
    sample_file.write_text(json.dumps(sample))

    with patch(
        "threat_intel_aggregator.OTX_SAMPLE_PATH", sample_file
    ):
        pulses = aggregator.load_otx_pulses()

    assert len(pulses) == 1
    assert pulses[0]["name"] == "Log4Shell campaign"


def test_load_otx_pulses_file_missing(aggregator: ThreatIntelAggregator, tmp_path: Path) -> None:
    """load_otx_pulses returns empty list when file does not exist."""
    missing = tmp_path / "nonexistent.json"
    with patch("threat_intel_aggregator.OTX_SAMPLE_PATH", missing):
        pulses = aggregator.load_otx_pulses()
    assert pulses == []


# ---------------------------------------------------------------------------
# 8. CVERecord dataclass
# ---------------------------------------------------------------------------


def test_cve_record_to_dict() -> None:
    """CVERecord.to_dict serialises all fields correctly."""
    rec = CVERecord(
        cve_id="CVE-2024-55555",
        severity="HIGH",
        cvss_score=8.1,
        description="Heap use-after-free",
        published="2024-02-01T00:00:00",
        last_modified="2024-02-02T00:00:00",
        affected_products=["cpe:2.3:a:vendor:product:*"],
        epss_score=0.25,
        epss_percentile=0.80,
        in_kev=False,
    )
    d = rec.to_dict()
    assert d["cve_id"] == "CVE-2024-55555"
    assert d["cvss_score"] == 8.1
    assert d["in_kev"] is False
    assert d["kev_due_date"] is None


# ---------------------------------------------------------------------------
# 9. Daily aggregation (end-to-end mock)
# ---------------------------------------------------------------------------


def test_aggregate_daily_mocked(aggregator: ThreatIntelAggregator) -> None:
    """aggregate_daily returns a ThreatIntelReport with correct counts."""
    mock_get = MagicMock()
    mock_post = MagicMock()

    nvd_resp = MagicMock()
    nvd_resp.json.return_value = NVD_RESPONSE_FIXTURE
    nvd_resp.raise_for_status = MagicMock()

    epss_resp = MagicMock()
    epss_resp.json.return_value = EPSS_RESPONSE_FIXTURE
    epss_resp.raise_for_status = MagicMock()

    kev_resp = MagicMock()
    kev_resp.json.return_value = KEV_RESPONSE_FIXTURE
    kev_resp.raise_for_status = MagicMock()

    # Feodo C2 blocklist (GET) — returns an empty list (no C2 IPs in test)
    feodo_resp = MagicMock()
    feodo_resp.json.return_value = []
    feodo_resp.raise_for_status = MagicMock()

    osv_resp = MagicMock()
    osv_resp.json.return_value = OSV_RESPONSE_FIXTURE
    osv_resp.raise_for_status = MagicMock()

    # GET: NVD, EPSS, KEV, Feodo (in that order)
    mock_get.side_effect = [nvd_resp, epss_resp, kev_resp, feodo_resp]
    # POST: OSV querybatch (single batch covering both ecosystems)
    mock_post.return_value = osv_resp

    with patch.object(aggregator._session, "get", mock_get), \
         patch.object(aggregator._session, "post", mock_post):
        report = aggregator.aggregate_daily()

    assert isinstance(report, ThreatIntelReport)
    assert report.total_cves == 1
    assert report.kev_count == 1
    assert report.critical_count == 1
    # 2 unique vulns returned by the querybatch mock across both ecosystems
    assert report.osv_count == 2
