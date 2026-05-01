"""Tests for Censys CVE-to-host search feed importer.

Tests:
1. Parse 5-host fixture JSON
2. CVE filter (list_hosts by cve_id)
3. Country filter (list_hosts by country)
4. Single-IP check (check_host)
5. Idempotent re-import (same payload twice = same store size)
6. Missing credentials: graceful warning + zero result, no exception

All tests use an in-memory store — no disk I/O, no network calls.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

import pytest

# ---------------------------------------------------------------------------
# Make suite-feeds importable
# ---------------------------------------------------------------------------

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)


# ---------------------------------------------------------------------------
# Fixture data — 5 hosts across 3 countries, 2 CVEs
# ---------------------------------------------------------------------------

_FIXTURE_PAYLOAD: Dict[str, Any] = {
    "result": {
        "hits": [
            {
                "ip": "203.0.113.10",
                "last_updated_at": "2026-04-26T10:00:00Z",
                "services": [
                    {
                        "port": 443,
                        "service_name": "HTTPS",
                        "software": [{"product": "nginx", "version": "1.18.0"}],
                        "vulnerabilities": [{"cve_id": "CVE-2021-44228"}],
                    }
                ],
                "location": {"country_code": "US"},
                "autonomous_system": {"asn": 15169},
            },
            {
                "ip": "203.0.113.11",
                "last_updated_at": "2026-04-25T08:00:00Z",
                "services": [
                    {
                        "port": 80,
                        "service_name": "HTTP",
                        "software": [{"product": "Apache", "version": "2.4.51"}],
                        "vulnerabilities": [
                            {"cve_id": "CVE-2021-44228"},
                            {"cve_id": "CVE-2022-22965"},
                        ],
                    }
                ],
                "location": {"country_code": "DE"},
                "autonomous_system": {"asn": 3320},
            },
            {
                "ip": "203.0.113.12",
                "last_updated_at": "2026-04-24T18:00:00Z",
                "services": [
                    {
                        "port": 8080,
                        "service_name": "HTTP",
                        "software": [],
                        "vulnerabilities": [{"cve_id": "CVE-2022-22965"}],
                    }
                ],
                "location": {"country_code": "BR"},
                "autonomous_system": {"asn": 7738},
            },
            {
                "ip": "203.0.113.13",
                "last_updated_at": "2026-04-23T12:00:00Z",
                "services": [
                    {
                        "port": 443,
                        "service_name": "HTTPS",
                        "software": [{"product": "Tomcat", "version": "9.0.55"}],
                        "vulnerabilities": [{"cve_id": "CVE-2021-44228"}],
                    }
                ],
                "location": {"country_code": "US"},
                "autonomous_system": {"asn": 7922},
            },
            {
                "ip": "203.0.113.14",
                "last_updated_at": "2026-04-22T06:00:00Z",
                "services": [
                    {
                        "port": 8443,
                        "service_name": "HTTPS",
                        "software": [],
                        "vulnerabilities": [{"cve_id": "CVE-2021-44228"}],
                    }
                ],
                "location": {"country_code": "DE"},
                "autonomous_system": {"asn": 3320},
            },
        ]
    }
}


# ---------------------------------------------------------------------------
# In-memory store shim
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    """Plain dict that satisfies the PersistentDict surface used by the importer."""

    def persist(self, key=None):
        pass


@pytest.fixture(autouse=True)
def _fresh_store(monkeypatch):
    """Replace the module-level _store with a fresh in-memory dict for every test."""
    from feeds.censys import importer as imp

    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _do_import(fixture: Optional[Dict[str, Any]] = None, cve_id: str = "CVE-2021-44228") -> Dict[str, Any]:
    """Run run_import with fixture data (no credentials required)."""
    from feeds.censys.importer import run_import

    return run_import(
        cve_id=cve_id,
        fixture_data=fixture if fixture is not None else _FIXTURE_PAYLOAD,
        force=True,
    )


# ---------------------------------------------------------------------------
# Test 1: Parse 5-host fixture JSON
# ---------------------------------------------------------------------------

def test_parse_five_host_fixture():
    from feeds.censys.importer import parse_hosts_response

    records = parse_hosts_response(_FIXTURE_PAYLOAD)
    assert len(records) == 5
    ips = {r["ip"] for r in records}
    assert "203.0.113.10" in ips
    assert "203.0.113.14" in ips

    # Spot-check first record
    r0 = next(r for r in records if r["ip"] == "203.0.113.10")
    assert r0["country"] == "US"
    assert r0["asn"] == 15169
    assert len(r0["services"]) == 1
    assert r0["services"][0]["port"] == 443
    assert r0["services"][0]["product"] == "nginx"
    assert "CVE-2021-44228" in r0["cve_ids"]


# ---------------------------------------------------------------------------
# Test 2: CVE filter
# ---------------------------------------------------------------------------

def test_cve_filter():
    from feeds.censys.importer import list_hosts

    _do_import()

    # CVE-2021-44228 appears in hosts .10, .11, .13, .14 — 4 hosts
    log4j_hosts = list_hosts(cve_id="CVE-2021-44228", limit=100)
    assert len(log4j_hosts) == 4, f"Expected 4, got {len(log4j_hosts)}: {[h['ip'] for h in log4j_hosts]}"

    # CVE-2022-22965 appears in hosts .11, .12 — 2 hosts
    spring_hosts = list_hosts(cve_id="CVE-2022-22965", limit=100)
    assert len(spring_hosts) == 2


# ---------------------------------------------------------------------------
# Test 3: Country filter
# ---------------------------------------------------------------------------

def test_country_filter():
    from feeds.censys.importer import list_hosts

    _do_import()

    us_hosts = list_hosts(country="US", limit=100)
    assert len(us_hosts) == 2
    for h in us_hosts:
        assert h["country"] == "US"

    de_hosts = list_hosts(country="DE", limit=100)
    assert len(de_hosts) == 2

    br_hosts = list_hosts(country="BR", limit=100)
    assert len(br_hosts) == 1
    assert br_hosts[0]["ip"] == "203.0.113.12"

    # Non-existent country
    none_hosts = list_hosts(country="ZZ", limit=100)
    assert len(none_hosts) == 0


# ---------------------------------------------------------------------------
# Test 4: Single-IP check
# ---------------------------------------------------------------------------

def test_single_ip_check():
    from feeds.censys.importer import check_host

    _do_import()

    hit = check_host("203.0.113.10")
    assert hit is not None
    assert hit["ip"] == "203.0.113.10"
    assert hit["country"] == "US"
    assert hit["asn"] == 15169
    assert "CVE-2021-44228" in hit["cve_ids"]

    miss = check_host("198.51.100.1")
    assert miss is None


# ---------------------------------------------------------------------------
# Test 5: Idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_reimport():
    from feeds.censys.importer import total_count

    _do_import()
    count_after_first = total_count()

    _do_import()
    count_after_second = total_count()

    assert count_after_first == count_after_second == 5


# ---------------------------------------------------------------------------
# Test 6: Missing credentials — graceful, no exception, no import
# ---------------------------------------------------------------------------

def test_missing_credentials_graceful(monkeypatch):
    from feeds.censys import importer as imp

    # Ensure env vars are absent
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)

    result = imp.run_import(
        cve_id="CVE-2021-44228",
        api_id="",
        api_secret="",
        fixture_data=None,  # no fixture — forces credential path
        force=True,
    )

    # Must return a valid summary dict, not raise
    assert isinstance(result, dict)
    assert "hosts" in result
    assert result["hosts"] == 0  # nothing imported
    assert "by_country" in result
    assert "by_cve" in result
