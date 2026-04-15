"""Tests for ThreatFeedAggregator — Threat Feed Aggregator Engine."""

import os
import pytest

from core.threat_feed_aggregator import ThreatFeedAggregator


@pytest.fixture
def agg(tmp_path):
    db = str(tmp_path / "feeds_test.db")
    return ThreatFeedAggregator(db_path=db)


@pytest.fixture
def source_data():
    return {
        "name": "AlienVault OTX",
        "feed_type": "ip_blocklist",
        "url": "https://otx.alienvault.com/api/v1/",
        "format": "json",
        "update_frequency_minutes": 30,
        "enabled": True,
        "reliability_score": 85,
    }


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "init_test.db")
    ThreatFeedAggregator(db_path=db)
    assert os.path.exists(db)


def test_init_tables_exist(agg):
    import sqlite3
    with sqlite3.connect(agg.db_path) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "feed_sources" in tables
    assert "feed_items" in tables
    assert "feed_subscriptions" in tables


# ---------------------------------------------------------------------------
# 2. add_feed_source / list_feed_sources
# ---------------------------------------------------------------------------

def test_add_feed_source_returns_source_id(agg, source_data):
    result = agg.add_feed_source("org1", source_data)
    assert "source_id" in result
    assert len(result["source_id"]) == 36  # UUID


def test_add_feed_source_fields(agg, source_data):
    result = agg.add_feed_source("org1", source_data)
    assert result["name"] == "AlienVault OTX"
    assert result["feed_type"] == "ip_blocklist"
    assert result["reliability_score"] == 85


def test_list_feed_sources_empty(agg):
    assert agg.list_feed_sources("org1") == []


def test_list_feed_sources_after_add(agg, source_data):
    agg.add_feed_source("org1", source_data)
    sources = agg.list_feed_sources("org1")
    assert len(sources) == 1


def test_list_feed_sources_filter_enabled(agg, source_data):
    agg.add_feed_source("org1", source_data)
    disabled = dict(source_data, name="Disabled Feed", enabled=False)
    agg.add_feed_source("org1", disabled)
    enabled_sources = agg.list_feed_sources("org1", enabled=True)
    assert len(enabled_sources) == 1
    assert all(s["enabled"] for s in enabled_sources)


def test_list_feed_sources_filter_disabled(agg, source_data):
    agg.add_feed_source("org1", source_data)
    disabled = dict(source_data, name="Disabled Feed", enabled=False)
    agg.add_feed_source("org1", disabled)
    disabled_sources = agg.list_feed_sources("org1", enabled=False)
    assert len(disabled_sources) == 1


def test_add_feed_source_invalid_type_defaults(agg):
    result = agg.add_feed_source("org1", {"name": "X", "feed_type": "bogus_type"})
    assert result["feed_type"] == "osint"


# ---------------------------------------------------------------------------
# 3. ingest_feed_item / list_feed_items
# ---------------------------------------------------------------------------

def test_ingest_feed_item_returns_item_id(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    item = agg.ingest_feed_item("org1", src["source_id"], {
        "feed_type": "ip_blocklist",
        "title": "Malicious IP",
        "description": "Known C2 server",
        "severity": "high",
        "iocs": ["1.2.3.4", "5.6.7.8"],
        "published_at": "2026-04-15T00:00:00Z",
    })
    assert "item_id" in item
    assert len(item["item_id"]) == 36


def test_ingest_feed_item_iocs_stored(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    item = agg.ingest_feed_item("org1", src["source_id"], {
        "iocs": ["10.0.0.1", "evil.example.com"],
        "published_at": "2026-04-15T00:00:00Z",
    })
    assert "10.0.0.1" in item["iocs"]


def test_ingest_item_bumps_source_count(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {"published_at": "2026-04-15T00:00:00Z"})
    sources = agg.list_feed_sources("org1")
    assert sources[0]["item_count"] == 1


def test_list_feed_items_by_type(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {
        "feed_type": "cve", "published_at": "2026-04-15T00:00:00Z"
    })
    agg.ingest_feed_item("org1", src["source_id"], {
        "feed_type": "malware", "published_at": "2026-04-15T00:00:00Z"
    })
    cve_items = agg.list_feed_items("org1", feed_type="cve", hours_back=240)
    assert len(cve_items) == 1
    assert cve_items[0]["feed_type"] == "cve"


def test_list_feed_items_by_severity(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {
        "severity": "critical", "published_at": "2026-04-15T00:00:00Z"
    })
    agg.ingest_feed_item("org1", src["source_id"], {
        "severity": "low", "published_at": "2026-04-15T00:00:00Z"
    })
    critical_items = agg.list_feed_items("org1", severity="critical", hours_back=240)
    assert len(critical_items) == 1


def test_list_feed_items_hours_back(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {"published_at": "2026-04-15T00:00:00Z"})
    # Request last 0 hours — should find nothing
    items = agg.list_feed_items("org1", hours_back=0)
    assert items == []


# ---------------------------------------------------------------------------
# 4. search_iocs
# ---------------------------------------------------------------------------

def test_search_iocs_found(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {
        "iocs": ["192.168.1.1", "malware.example.com"],
        "published_at": "2026-04-15T00:00:00Z",
    })
    results = agg.search_iocs("org1", "malware.example.com")
    assert len(results) == 1
    assert "malware.example.com" in results[0]["matched_iocs"]


def test_search_iocs_not_found(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {
        "iocs": ["10.0.0.1"],
        "published_at": "2026-04-15T00:00:00Z",
    })
    results = agg.search_iocs("org1", "totally-different.com")
    assert results == []


def test_search_iocs_empty_query(agg):
    results = agg.search_iocs("org1", "")
    assert results == []


def test_search_iocs_partial_match(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {
        "iocs": ["192.168.100.1", "192.168.200.1"],
        "published_at": "2026-04-15T00:00:00Z",
    })
    results = agg.search_iocs("org1", "192.168")
    assert len(results) == 1
    assert len(results[0]["matched_iocs"]) == 2


# ---------------------------------------------------------------------------
# 5. get_feed_stats
# ---------------------------------------------------------------------------

def test_get_feed_stats_empty(agg):
    stats = agg.get_feed_stats("org1")
    assert stats["total_sources"] == 0
    assert stats["active_sources"] == 0
    assert stats["items_24h"] == 0
    assert stats["items_7d"] == 0


def test_get_feed_stats_with_data(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {
        "feed_type": "ip_blocklist", "published_at": "2026-04-15T00:00:00Z"
    })
    stats = agg.get_feed_stats("org1")
    assert stats["total_sources"] == 1
    assert stats["active_sources"] == 1
    assert stats["items_24h"] >= 1
    assert "by_feed_type" in stats
    assert "avg_reliability" in stats


def test_get_feed_stats_by_feed_type(agg, source_data):
    src = agg.add_feed_source("org1", source_data)
    agg.ingest_feed_item("org1", src["source_id"], {"feed_type": "cve", "published_at": "2026-04-15T00:00:00Z"})
    agg.ingest_feed_item("org1", src["source_id"], {"feed_type": "cve", "published_at": "2026-04-15T00:00:00Z"})
    agg.ingest_feed_item("org1", src["source_id"], {"feed_type": "malware", "published_at": "2026-04-15T00:00:00Z"})
    stats = agg.get_feed_stats("org1")
    assert stats["by_feed_type"].get("cve") == 2
    assert stats["by_feed_type"].get("malware") == 1


# ---------------------------------------------------------------------------
# 6. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_sources(agg, source_data):
    agg.add_feed_source("org_a", source_data)
    assert agg.list_feed_sources("org_b") == []


def test_org_isolation_items(agg, source_data):
    src = agg.add_feed_source("org_a", source_data)
    agg.ingest_feed_item("org_a", src["source_id"], {"published_at": "2026-04-15T00:00:00Z"})
    items_b = agg.list_feed_items("org_b", hours_back=240)
    assert items_b == []


def test_org_isolation_search(agg, source_data):
    src = agg.add_feed_source("org_a", source_data)
    agg.ingest_feed_item("org_a", src["source_id"], {
        "iocs": ["secret-ip.example.com"],
        "published_at": "2026-04-15T00:00:00Z",
    })
    results = agg.search_iocs("org_b", "secret-ip.example.com")
    assert results == []
