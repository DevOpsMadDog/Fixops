"""Tests for SecurityTrails passive DNS importer.

Uses --use-fixture pattern (fixture kwarg) so no real API calls are made.
All 6 test cases pass without SECURITYTRAILS_API_KEY set.

Run:
    pytest tests/test_securitytrails_importer.py -v --timeout=10
"""

from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Ensure suite-feeds and suite-core are importable
_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
for _path in [
    str(_PROJECT_ROOT / "suite-feeds"),
    str(_PROJECT_ROOT / "suite-core"),
]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

# ---------------------------------------------------------------------------
# Fixture data (5 domains)
# ---------------------------------------------------------------------------

FIXTURE_DOMAINS: List[Dict[str, Any]] = [
    {
        "domain": "alpha.test",
        "subdomains_payload": {"subdomains": ["www", "api", "mail", "vpn", "dev"]},
        "history_payload": {
            "records": [
                {
                    "type": "a",
                    "first_seen": "2023-01-01",
                    "last_seen": "2024-01-01",
                    "values": [{"ip": "1.2.3.4"}],
                },
                {
                    "type": "a",
                    "first_seen": "2024-01-02",
                    "last_seen": "2024-06-01",
                    "values": [{"ip": "5.6.7.8"}],
                },
            ]
        },
    },
    {
        "domain": "beta.test",
        "subdomains_payload": {"subdomains": ["www", "staging"]},
        "history_payload": {
            "records": [
                {
                    "type": "a",
                    "first_seen": "2022-03-01",
                    "last_seen": "2023-03-01",
                    "values": [{"ip": "10.0.0.1"}],
                },
            ]
        },
    },
    {
        "domain": "gamma.test",
        "subdomains_payload": {"subdomains": ["api", "cdn", "blog"]},
        "history_payload": {"records": []},
    },
    {
        "domain": "delta.test",
        "subdomains_payload": {"subdomains": []},
        "history_payload": {"records": []},
    },
    {
        "domain": "epsilon.test",
        "subdomains_payload": {"subdomains": ["admin", "portal", "auth", "status", "docs", "support"]},
        "history_payload": {
            "records": [
                {
                    "type": "a",
                    "first_seen": "2021-01-01",
                    "last_seen": "2025-01-01",
                    "values": [{"ip": "192.168.100.5"}],
                },
            ]
        },
    },
]

RDNS_FIXTURE = {
    "1.2.3.4": {"records": [{"hostname": "host.alpha.test"}, {"hostname": "mx.alpha.test"}]},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fixture(domain_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Convert raw fixture payload into the fixture dict expected by enumerate_domain."""
    from feeds.securitytrails.importer import (
        parse_subdomains_response,
        parse_dns_history_response,
    )
    subdomains = parse_subdomains_response(domain_entry["subdomains_payload"])
    dns_data = parse_dns_history_response(domain_entry["history_payload"])
    return {"subdomains": subdomains, "history": dns_data}


def _fresh_store(tmp_path: Path) -> str:
    """Return a path to a fresh SQLite store per test."""
    return str(tmp_path / "securitytrails_test.db")


# ---------------------------------------------------------------------------
# Test 1: Parse 5-domain fixture JSON
# ---------------------------------------------------------------------------

class TestParseFixtureJSON:
    """Parse all 5 fixture domains and verify record shapes."""

    def test_parse_all_5_domains(self, tmp_path: Path) -> None:
        from feeds.securitytrails.importer import enumerate_domain

        db = _fresh_store(tmp_path)
        results = []
        for entry in FIXTURE_DOMAINS:
            fixture = _make_fixture(entry)
            record = enumerate_domain(entry["domain"], fixture=fixture, db_path=db)
            results.append(record)

        assert len(results) == 5
        for record in results:
            assert "domain" in record
            assert "subdomain_count" in record
            assert isinstance(record["subdomains"], list)
            assert isinstance(record["current_a_records"], list)
            assert isinstance(record["historical_a_records"], list)
            assert record["status"] == "ok"
            assert "cached_at" in record
            assert "imported_at" in record


# ---------------------------------------------------------------------------
# Test 2: Subdomain extraction
# ---------------------------------------------------------------------------

class TestSubdomainExtraction:
    def test_subdomain_count_matches(self, tmp_path: Path) -> None:
        from feeds.securitytrails.importer import enumerate_domain

        db = _fresh_store(tmp_path)
        entry = FIXTURE_DOMAINS[0]  # alpha.test — 5 subdomains
        fixture = _make_fixture(entry)
        record = enumerate_domain(entry["domain"], fixture=fixture, db_path=db)

        assert record["subdomain_count"] == 5
        assert set(record["subdomains"]) == {"www", "api", "mail", "vpn", "dev"}

    def test_subdomain_extraction_via_parser(self) -> None:
        from feeds.securitytrails.importer import parse_subdomains_response

        payload = {"subdomains": ["WWW", "API", "mail"]}
        result = parse_subdomains_response(payload)
        assert result == ["www", "api", "mail"]

    def test_empty_subdomains(self, tmp_path: Path) -> None:
        from feeds.securitytrails.importer import enumerate_domain

        db = _fresh_store(tmp_path)
        entry = FIXTURE_DOMAINS[3]  # delta.test — 0 subdomains
        fixture = _make_fixture(entry)
        record = enumerate_domain(entry["domain"], fixture=fixture, db_path=db)

        assert record["subdomain_count"] == 0
        assert record["subdomains"] == []


# ---------------------------------------------------------------------------
# Test 3: DNS history extraction
# ---------------------------------------------------------------------------

class TestDNSHistoryExtraction:
    def test_history_records_parsed(self, tmp_path: Path) -> None:
        from feeds.securitytrails.importer import enumerate_domain

        db = _fresh_store(tmp_path)
        entry = FIXTURE_DOMAINS[0]  # alpha.test — 2 historical records
        fixture = _make_fixture(entry)
        record = enumerate_domain(entry["domain"], fixture=fixture, db_path=db)

        hist = record["historical_a_records"]
        assert len(hist) == 2
        ips = {r["ip"] for r in hist}
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips
        for r in hist:
            assert "first_seen" in r
            assert "last_seen" in r

    def test_parse_dns_history_response_directly(self) -> None:
        from feeds.securitytrails.importer import parse_dns_history_response

        payload = {
            "records": [
                {
                    "type": "a",
                    "first_seen": "2023-01-01",
                    "last_seen": "2023-12-31",
                    "values": [{"ip": "9.9.9.9"}],
                }
            ]
        }
        result = parse_dns_history_response(payload)
        assert result["historical_a_records"][0]["ip"] == "9.9.9.9"
        assert result["historical_a_records"][0]["first_seen"] == "2023-01-01"

    def test_non_a_records_excluded(self) -> None:
        from feeds.securitytrails.importer import parse_dns_history_response

        payload = {
            "records": [
                {
                    "type": "mx",
                    "first_seen": "2023-01-01",
                    "last_seen": "2023-12-31",
                    "values": [{"value": "mail.example.com"}],
                }
            ]
        }
        result = parse_dns_history_response(payload)
        assert result["historical_a_records"] == []


# ---------------------------------------------------------------------------
# Test 4: Reverse DNS lookup
# ---------------------------------------------------------------------------

class TestReverseDNSLookup:
    def test_rdns_fixture(self, tmp_path: Path) -> None:
        from feeds.securitytrails.importer import lookup_ip, parse_rdns_response

        db = _fresh_store(tmp_path)
        ip = "1.2.3.4"
        fixture_payload = RDNS_FIXTURE[ip]
        hostnames = parse_rdns_response(fixture_payload)
        fixture = {"hostnames": hostnames}

        record = lookup_ip(ip, fixture=fixture, db_path=db)
        assert record["ip"] == ip
        assert "host.alpha.test" in record["hostnames"]
        assert "mx.alpha.test" in record["hostnames"]
        assert record["status"] == "ok"

    def test_parse_rdns_response_directly(self) -> None:
        from feeds.securitytrails.importer import parse_rdns_response

        payload = {"records": [{"hostname": "foo.example.com"}, {"hostname": "bar.example.com"}]}
        result = parse_rdns_response(payload)
        assert "foo.example.com" in result
        assert "bar.example.com" in result

    def test_parse_rdns_hostname_shape(self) -> None:
        from feeds.securitytrails.importer import parse_rdns_response

        payload = {"hostnames": ["baz.example.net", "qux.example.net"]}
        result = parse_rdns_response(payload)
        assert "baz.example.net" in result


# ---------------------------------------------------------------------------
# Test 5: Cache hit on second call
# ---------------------------------------------------------------------------

class TestCacheHit:
    def test_second_call_returns_cached(self, tmp_path: Path) -> None:
        from feeds.securitytrails.importer import enumerate_domain, get_domain_report

        db = _fresh_store(tmp_path)
        entry = FIXTURE_DOMAINS[1]  # beta.test
        fixture = _make_fixture(entry)

        # First call — populates cache
        first = enumerate_domain(entry["domain"], fixture=fixture, db_path=db)
        assert first["status"] == "ok"

        # Second call without fixture — should serve from cache (no API call needed)
        second = enumerate_domain(entry["domain"], db_path=db)
        assert second["status"] == "ok"
        assert second["domain"] == first["domain"]
        assert second["subdomain_count"] == first["subdomain_count"]
        assert second["cached_at"] == first["cached_at"]  # same timestamp = cache hit

    def test_get_domain_report_returns_cached(self, tmp_path: Path) -> None:
        from feeds.securitytrails.importer import enumerate_domain, get_domain_report

        db = _fresh_store(tmp_path)
        entry = FIXTURE_DOMAINS[2]  # gamma.test
        fixture = _make_fixture(entry)

        enumerate_domain(entry["domain"], fixture=fixture, db_path=db)
        report = get_domain_report(entry["domain"], db_path=db)
        assert report is not None
        assert report["domain"] == entry["domain"]

    def test_rdns_cache_hit(self, tmp_path: Path) -> None:
        from feeds.securitytrails.importer import lookup_ip, get_ip_report

        db = _fresh_store(tmp_path)
        ip = "1.2.3.4"
        fixture = {"hostnames": ["cached.example.com"]}

        lookup_ip(ip, fixture=fixture, db_path=db)
        cached = get_ip_report(ip, db_path=db)
        assert cached is not None
        assert "cached.example.com" in cached["hostnames"]


# ---------------------------------------------------------------------------
# Test 6: Missing credentials — graceful degradation
# ---------------------------------------------------------------------------

class TestMissingCredentials:
    def test_enumerate_domain_no_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without API key and no fixture, enumerate_domain returns needs_credentials."""
        monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
        from feeds.securitytrails import importer
        # Reload to clear cached key
        import importlib
        importlib.reload(importer)

        db = _fresh_store(tmp_path)
        record = importer.enumerate_domain("example.com", db_path=db)
        assert record["status"] == "needs_credentials"
        assert record["subdomain_count"] == 0
        assert record["subdomains"] == []

    def test_lookup_ip_no_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without API key and no fixture, lookup_ip returns needs_credentials."""
        monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
        from feeds.securitytrails import importer
        import importlib
        importlib.reload(importer)

        db = _fresh_store(tmp_path)
        record = importer.lookup_ip("8.8.8.8", db_path=db)
        assert record["status"] == "needs_credentials"
        assert record["hostnames"] == []

    def test_run_import_no_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_import returns needs_credentials and zero counts without a key."""
        monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
        from feeds.securitytrails import importer
        import importlib
        importlib.reload(importer)

        result = importer.run_import(domains=["example.com"])
        assert result["status"] == "needs_credentials"
        assert result["domains_processed"] == 0
        assert result["subdomains_total"] == 0
        assert result["ips_resolved"] == 0
