"""Tests for the Threat Intel unified API router.

Covers: IOC list/lookup, feed status, feed summary, bulk lookup,
trending threats, campaigns, geo/IP endpoints.

All tests use mocks — no external API calls, no live DB required.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Configure environment before any imports
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# Ensure suite paths on sys.path
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-api")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-feeds")

from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Minimal mocks for heavy dependencies before importing the router
# ---------------------------------------------------------------------------

_mock_correlator = MagicMock()
_mock_correlator._load_all_actors.return_value = []
_mock_correlator.correlate_finding.return_value = MagicMock(
    actor_id=None, campaign_id=None, confidence=0.0, matched_ttps=[]
)
_mock_correlator.correlate_batch.return_value = []

_mock_aggregator = MagicMock()
_mock_aggregator.get_cached_cves.return_value = []
_mock_aggregator._load_kev_from_cache.return_value = {}
_mock_aggregator.check_ip_abuseipdb.return_value = {}
_mock_aggregator.aggregate_daily.return_value = MagicMock(
    generated_at="2026-04-16T00:00:00Z",
    total_cves=10,
    kev_count=2,
    critical_count=1,
    high_count=3,
    avg_epss=0.05,
    osv_count=5,
    otx_pulses=0,
)

with (
    patch("core.threat_intel_correlator.ThreatIntelCorrelator", return_value=_mock_correlator),
    patch("threat_intel_aggregator.ThreatIntelAggregator", return_value=_mock_aggregator),
):
    from apps.api.threat_intel_router import router

app = FastAPI()
app.include_router(router)
client = TestClient(app, raise_server_exceptions=True)

BASE = "/api/v1/threat-intel"


# ---------------------------------------------------------------------------
# Helper: patch DB helpers to avoid needing a real sqlite file
# ---------------------------------------------------------------------------

ROUTER_MODULE = "apps.api.threat_intel_router"


def _patch_db(
    feodo_count=0,
    feodo_last=None,
    kev_count=0,
    osv_count=0,
    feodo_rows=None,
    feodo_lookup=None,
    kev_lookup=None,
):
    patches = [
        patch(f"{ROUTER_MODULE}._get_feodo_count", return_value=feodo_count),
        patch(f"{ROUTER_MODULE}._get_feodo_last_updated", return_value=feodo_last),
        patch(f"{ROUTER_MODULE}._get_kev_count", return_value=kev_count),
        patch(f"{ROUTER_MODULE}._get_osv_count", return_value=osv_count),
        patch(f"{ROUTER_MODULE}._lookup_feodo", return_value=feodo_lookup),
        patch(f"{ROUTER_MODULE}._lookup_kev", return_value=kev_lookup),
    ]
    return patches


# ---------------------------------------------------------------------------
# /iocs — list IOCs
# ---------------------------------------------------------------------------


class TestListIOCs:
    def test_returns_empty_when_no_db(self):
        with patch(f"{ROUTER_MODULE}._FEEDS_DB") as mock_db:
            mock_db.exists.return_value = False
            resp = client.get(f"{BASE}/iocs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["iocs"] == []

    def test_returns_iocs_from_db(self):
        import sqlite3
        import tempfile
        from pathlib import Path

        # Build a temporary DB with one feodo row
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)

        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """CREATE TABLE feodo_c2_cache
               (ip_address TEXT PRIMARY KEY, port INTEGER, status TEXT,
                malware TEXT, country TEXT, first_seen TEXT, last_online TEXT,
                fetched_at REAL NOT NULL)"""
        )
        conn.execute(
            "INSERT INTO feodo_c2_cache VALUES (?,?,?,?,?,?,?,?)",
            ("1.2.3.4", 443, "online", "Emotet", "DE", "2026-01-01", "2026-04-15", 1713225600.0),
        )
        conn.commit()
        conn.close()

        with patch(f"{ROUTER_MODULE}._FEEDS_DB", db_path):
            resp = client.get(f"{BASE}/iocs")

        db_path.unlink(missing_ok=True)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert data["iocs"][0]["value"] == "1.2.3.4"
        assert data["iocs"][0]["ioc_type"] == "ip"

    def test_pagination_params(self):
        with patch(f"{ROUTER_MODULE}._FEEDS_DB") as mock_db:
            mock_db.exists.return_value = False
            resp = client.get(f"{BASE}/iocs?limit=10&offset=5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["limit"] == 10
        assert data["offset"] == 5

    def test_search_filter_param_accepted(self):
        with patch(f"{ROUTER_MODULE}._FEEDS_DB") as mock_db:
            mock_db.exists.return_value = False
            resp = client.get(f"{BASE}/iocs?search=1.2.3")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /iocs/lookup — single IOC lookup
# ---------------------------------------------------------------------------


class TestIOCLookup:
    def test_lookup_unknown_ip(self):
        for p in _patch_db(feodo_lookup=None, kev_lookup=None):
            p.start()
        try:
            resp = client.post(f"{BASE}/iocs/lookup", json={"value": "10.0.0.1"})
        finally:
            patch.stopall()

        assert resp.status_code == 200
        data = resp.json()
        assert data["value"] == "10.0.0.1"
        assert data["ioc_type"] == "ip"
        assert data["found"] is False
        assert data["hits"] == []

    def test_lookup_known_c2_ip(self):
        feodo_hit = {
            "source": "feodo_c2",
            "ip_address": "5.5.5.5",
            "port": 443,
            "status": "online",
            "malware": "Emotet",
            "country": "DE",
            "first_seen": "2026-01-01",
            "last_online": "2026-04-15",
        }
        for p in _patch_db(feodo_lookup=feodo_hit, kev_lookup=None):
            p.start()
        try:
            resp = client.post(f"{BASE}/iocs/lookup", json={"value": "5.5.5.5"})
        finally:
            patch.stopall()

        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is True
        assert len(data["hits"]) == 1
        assert data["hits"][0]["source"] == "feodo_c2"

    def test_lookup_cve_in_kev(self):
        kev_hit = {"source": "cisa_kev", "cve_id": "CVE-2021-44228", "due_date": "2021-12-24"}
        for p in _patch_db(feodo_lookup=None, kev_lookup=kev_hit):
            p.start()
        try:
            resp = client.post(f"{BASE}/iocs/lookup", json={"value": "CVE-2021-44228"})
        finally:
            patch.stopall()

        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is True
        assert data["hits"][0]["source"] == "cisa_kev"

    def test_lookup_empty_value_returns_422(self):
        resp = client.post(f"{BASE}/iocs/lookup", json={"value": ""})
        assert resp.status_code == 422

    def test_lookup_hash_ioc_type_detection(self):
        for p in _patch_db(feodo_lookup=None, kev_lookup=None):
            p.start()
        try:
            sha256 = "a" * 64
            resp = client.post(f"{BASE}/iocs/lookup", json={"value": sha256})
        finally:
            patch.stopall()
        assert resp.status_code == 200
        assert resp.json()["ioc_type"] == "hash"

    def test_lookup_url_ioc_type_detection(self):
        for p in _patch_db(feodo_lookup=None, kev_lookup=None):
            p.start()
        try:
            resp = client.post(
                f"{BASE}/iocs/lookup",
                json={"value": "http://malicious.example.com/payload"},
            )
        finally:
            patch.stopall()
        assert resp.status_code == 200
        assert resp.json()["ioc_type"] == "url"

    def test_feeds_checked_field_present(self):
        for p in _patch_db(feodo_lookup=None, kev_lookup=None):
            p.start()
        try:
            resp = client.post(f"{BASE}/iocs/lookup", json={"value": "192.168.1.1"})
        finally:
            patch.stopall()
        assert "feeds_checked" in resp.json()


# ---------------------------------------------------------------------------
# /feeds/status
# ---------------------------------------------------------------------------


class TestFeedsStatus:
    def test_returns_all_feeds(self):
        for p in _patch_db(feodo_count=620, kev_count=1100, osv_count=450):
            p.start()
        try:
            resp = client.get(f"{BASE}/feeds/status")
        finally:
            patch.stopall()

        assert resp.status_code == 200
        data = resp.json()
        assert "feeds" in data
        names = [f["name"] for f in data["feeds"]]
        assert "Feodo C2 Blocklist" in names
        assert "CISA KEV" in names
        assert "OTX AlienVault" in names
        assert "AbuseIPDB" in names
        assert "OSV" in names

    def test_feodo_healthy_when_count_positive(self):
        for p in _patch_db(feodo_count=620, kev_count=1100, osv_count=0):
            p.start()
        try:
            resp = client.get(f"{BASE}/feeds/status")
        finally:
            patch.stopall()
        feeds = {f["source"]: f for f in resp.json()["feeds"]}
        assert feeds["feodo_c2"]["health"] == "healthy"

    def test_otx_no_api_key_status(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OTX_API_KEY", None)
            for p in _patch_db(feodo_count=0, kev_count=0, osv_count=0):
                p.start()
            try:
                resp = client.get(f"{BASE}/feeds/status")
            finally:
                patch.stopall()
        feeds = {f["source"]: f for f in resp.json()["feeds"]}
        assert feeds["otx"]["health"] == "no_api_key"

    def test_summary_fields_present(self):
        for p in _patch_db(feodo_count=620, kev_count=1100, osv_count=0):
            p.start()
        try:
            resp = client.get(f"{BASE}/feeds/status")
        finally:
            patch.stopall()
        data = resp.json()
        assert "total_feeds" in data
        assert "healthy_feeds" in data
        assert "degraded_feeds" in data


# ---------------------------------------------------------------------------
# /feeds/summary
# ---------------------------------------------------------------------------


class TestFeedsSummary:
    def test_returns_total_and_breakdown(self):
        for p in _patch_db(feodo_count=620, kev_count=1100, osv_count=450):
            p.start()
        try:
            resp = client.get(f"{BASE}/feeds/summary")
        finally:
            patch.stopall()
        assert resp.status_code == 200
        data = resp.json()
        assert "total_iocs" in data
        assert "by_type" in data
        assert "by_source" in data
        assert data["total_iocs"] > 0

    def test_by_type_has_ip_key(self):
        for p in _patch_db(feodo_count=620, kev_count=1100, osv_count=0):
            p.start()
        try:
            data = client.get(f"{BASE}/feeds/summary").json()
        finally:
            patch.stopall()
        assert "ip" in data["by_type"]
        assert "cve" in data["by_type"]


# ---------------------------------------------------------------------------
# /iocs/bulk-lookup
# ---------------------------------------------------------------------------


class TestBulkLookup:
    def test_bulk_lookup_returns_per_value_results(self):
        for p in _patch_db(feodo_lookup=None, kev_lookup=None):
            p.start()
        try:
            resp = client.post(
                f"{BASE}/iocs/bulk-lookup",
                json={"values": ["10.0.0.1", "10.0.0.2"]},
            )
        finally:
            patch.stopall()
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["results"]) == 2

    def test_bulk_lookup_empty_list_returns_422(self):
        resp = client.post(f"{BASE}/iocs/bulk-lookup", json={"values": []})
        assert resp.status_code == 422

    def test_bulk_lookup_over_100_returns_422(self):
        resp = client.post(
            f"{BASE}/iocs/bulk-lookup",
            json={"values": [f"10.0.{i}.{j}" for i in range(10) for j in range(11)]},
        )
        assert resp.status_code == 422

    def test_bulk_lookup_found_count(self):
        feodo_hit = {"source": "feodo_c2", "ip_address": "5.5.5.5"}
        with patch(f"{ROUTER_MODULE}._lookup_feodo", return_value=feodo_hit), \
             patch(f"{ROUTER_MODULE}._lookup_kev", return_value=None):
            resp = client.post(
                f"{BASE}/iocs/bulk-lookup",
                json={"values": ["5.5.5.5", "8.8.8.8"]},
            )
        data = resp.json()
        assert data["found"] >= 1


# ---------------------------------------------------------------------------
# /trending
# ---------------------------------------------------------------------------


class TestTrending:
    def test_returns_trending_structure(self):
        with patch(f"{ROUTER_MODULE}._FEEDS_DB") as mock_db:
            mock_db.exists.return_value = False
            resp = client.get(f"{BASE}/trending")
        assert resp.status_code == 200
        data = resp.json()
        assert "trending" in data
        assert "period" in data
        assert data["period"] == "7d"

    def test_limit_param_accepted(self):
        with patch(f"{ROUTER_MODULE}._FEEDS_DB") as mock_db:
            mock_db.exists.return_value = False
            resp = client.get(f"{BASE}/trending?limit=5")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /campaigns
# ---------------------------------------------------------------------------


class TestCampaigns:
    def test_returns_empty_when_no_actors(self):
        _mock_correlator._load_all_actors.return_value = []
        resp = client.get(f"{BASE}/campaigns")
        assert resp.status_code == 200
        data = resp.json()
        assert "campaigns" in data
        assert "total" in data

    def test_returns_campaigns_from_actors(self):
        actor = MagicMock()
        actor.id = "apt29"
        actor.name = "Cozy Bear"
        actor.active = True
        actor.known_campaigns = ["campaign-001", "campaign-002"]
        _mock_correlator._load_all_actors.return_value = [actor]

        resp = client.get(f"{BASE}/campaigns")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert any(c["campaign_id"] == "campaign-001" for c in data["campaigns"])

        # Restore
        _mock_correlator._load_all_actors.return_value = []


# ---------------------------------------------------------------------------
# /geo/{ip}
# ---------------------------------------------------------------------------


class TestGeoIP:
    def test_invalid_ip_returns_422(self):
        resp = client.get(f"{BASE}/geo/not-an-ip")
        assert resp.status_code == 422

    def test_valid_ip_returns_structure(self):
        with patch(f"{ROUTER_MODULE}._lookup_feodo", return_value=None), \
             patch(f"{ROUTER_MODULE}._aggregator") as mock_agg, \
             patch("core.cve_enrichment.CVEEnrichmentService") as mock_enr:
            mock_agg.check_ip_abuseipdb.return_value = {}
            mock_enr.return_value.enrich_ip.return_value = {
                "ip": "8.8.8.8", "ports": [53], "hostnames": ["dns.google"],
                "cpes": [], "tags": [], "vulns": [], "source": "shodan",
                "enriched_at": "2026-04-16T00:00:00",
            }
            resp = client.get(f"{BASE}/geo/8.8.8.8")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ip"] == "8.8.8.8"
        assert "is_c2" in data

    def test_c2_ip_flagged(self):
        feodo_hit = {
            "source": "feodo_c2", "ip_address": "5.5.5.5", "port": 443,
            "status": "online", "malware": "Emotet", "country": "DE",
            "first_seen": "2026-01-01", "last_online": "2026-04-15",
        }
        with patch(f"{ROUTER_MODULE}._lookup_feodo", return_value=feodo_hit), \
             patch(f"{ROUTER_MODULE}._aggregator") as mock_agg, \
             patch("core.cve_enrichment.CVEEnrichmentService") as mock_enr:
            mock_agg.check_ip_abuseipdb.return_value = {}
            mock_enr.return_value.enrich_ip.side_effect = Exception("no network")
            resp = client.get(f"{BASE}/geo/5.5.5.5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_c2"] is True
        assert data["malware"] == "Emotet"
