"""Tests for ThreatIntelPlatformEngine — 30+ tests covering all major paths."""

from __future__ import annotations

import json
import tempfile
import pytest
from pathlib import Path


@pytest.fixture
def tip_engine(tmp_path):
    from core.threat_intel_platform_engine import ThreatIntelPlatformEngine
    return ThreatIntelPlatformEngine(db_dir=str(tmp_path))


ORG = "test-org-tip"
ORG2 = "other-org-tip"


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def test_add_source_basic(tip_engine):
    src = tip_engine.add_source(ORG, {"source_name": "AlienVault OTX", "source_type": "osint"})
    assert src["id"]
    assert src["source_name"] == "AlienVault OTX"
    assert src["source_type"] == "osint"
    assert src["status"] == "active"


def test_add_source_all_fields(tip_engine):
    src = tip_engine.add_source(ORG, {
        "source_name": "Recorded Future",
        "source_type": "commercial",
        "feed_url": "https://api.rf.io/feed",
        "api_key_masked": "rf_***",
        "reliability_score": 0.9,
        "update_frequency_hours": 1,
        "total_indicators": 1000,
    })
    assert src["source_type"] == "commercial"
    assert src["reliability_score"] == 0.9


def test_add_source_missing_name(tip_engine):
    with pytest.raises(ValueError, match="source_name"):
        tip_engine.add_source(ORG, {"source_type": "osint"})


def test_add_source_invalid_type(tip_engine):
    with pytest.raises(ValueError):
        tip_engine.add_source(ORG, {"source_name": "X", "source_type": "unknown"})


def test_list_sources_empty(tip_engine):
    result = tip_engine.list_sources(ORG)
    assert result == []


def test_list_sources_filtered(tip_engine):
    tip_engine.add_source(ORG, {"source_name": "A", "source_type": "osint", "status": "active"})
    tip_engine.add_source(ORG, {"source_name": "B", "source_type": "isac", "status": "inactive"})
    active = tip_engine.list_sources(ORG, status="active")
    assert len(active) == 1
    assert active[0]["source_name"] == "A"


def test_list_sources_org_isolation(tip_engine):
    tip_engine.add_source(ORG, {"source_name": "Org1Source"})
    sources_org2 = tip_engine.list_sources(ORG2)
    assert len(sources_org2) == 0


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

def test_add_indicator_ip(tip_engine):
    ind = tip_engine.add_indicator(ORG, {
        "indicator_type": "ip",
        "value": "1.2.3.4",
        "severity": "high",
        "threat_category": "c2",
        "confidence": 0.8,
    })
    assert ind["id"]
    assert ind["indicator_type"] == "ip"
    assert ind["value"] == "1.2.3.4"
    assert ind["active"] is True


def test_add_indicator_domain(tip_engine):
    ind = tip_engine.add_indicator(ORG, {
        "indicator_type": "domain",
        "value": "evil.example.com",
        "threat_category": "phishing",
        "tlp_level": "amber",
    })
    assert ind["indicator_type"] == "domain"


def test_add_indicator_duplicate_returns_existing(tip_engine):
    tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "5.5.5.5", "threat_category": "malware"})
    result = tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "5.5.5.5", "threat_category": "malware"})
    assert result.get("_duplicate") is True


def test_add_indicator_missing_value(tip_engine):
    with pytest.raises(ValueError, match="value"):
        tip_engine.add_indicator(ORG, {"indicator_type": "ip"})


def test_add_indicator_invalid_type(tip_engine):
    with pytest.raises(ValueError):
        tip_engine.add_indicator(ORG, {"indicator_type": "unknown", "value": "x"})


def test_add_indicator_invalid_severity(tip_engine):
    with pytest.raises(ValueError):
        tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "1.1.1.1", "severity": "extreme"})


def test_add_indicator_with_tags_and_mitre(tip_engine):
    ind = tip_engine.add_indicator(ORG, {
        "indicator_type": "file_hash",
        "value": "deadbeef" * 8,
        "threat_category": "malware",
        "tags": ["ransomware", "lockbit"],
        "mitre_techniques": ["T1486", "T1059"],
    })
    assert isinstance(ind["tags"], list)
    assert "ransomware" in ind["tags"]
    assert "T1486" in ind["mitre_techniques"]


def test_search_indicators_by_value(tip_engine):
    tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "192.168.100.1", "threat_category": "scanner"})
    tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "10.0.0.1", "threat_category": "botnet"})
    results = tip_engine.search_indicators(ORG, "192.168")
    assert len(results) == 1
    assert results[0]["value"] == "192.168.100.1"


def test_search_indicators_with_type_filter(tip_engine):
    tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "1.1.1.100", "threat_category": "c2"})
    tip_engine.add_indicator(ORG, {"indicator_type": "domain", "value": "1.1.1.100.evil.com", "threat_category": "c2"})
    results = tip_engine.search_indicators(ORG, "1.1.1.100", indicator_type="ip")
    assert all(r["indicator_type"] == "ip" for r in results)


def test_get_indicator(tip_engine):
    ind = tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "7.7.7.7", "threat_category": "apt"})
    result = tip_engine.get_indicator(ORG, ind["id"])
    assert result is not None
    assert result["id"] == ind["id"]
    assert "relationships" in result


def test_get_indicator_not_found(tip_engine):
    assert tip_engine.get_indicator(ORG, "nonexistent-id") is None


def test_get_indicator_org_isolation(tip_engine):
    ind = tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "9.9.9.9", "threat_category": "scanner"})
    assert tip_engine.get_indicator(ORG2, ind["id"]) is None


# ---------------------------------------------------------------------------
# Bulk ingest
# ---------------------------------------------------------------------------

def test_bulk_ingest(tip_engine):
    src = tip_engine.add_source(ORG, {"source_name": "Bulk Test"})
    indicators = [
        {"indicator_type": "ip", "value": "10.1.1.1", "threat_category": "botnet"},
        {"indicator_type": "ip", "value": "10.1.1.2", "threat_category": "botnet"},
        {"indicator_type": "domain", "value": "bad.example.com", "threat_category": "phishing"},
    ]
    result = tip_engine.bulk_ingest(ORG, src["id"], indicators)
    assert result["added"] == 3
    assert result["duplicates"] == 0
    assert result["errors"] == 0


def test_bulk_ingest_with_duplicates(tip_engine):
    src = tip_engine.add_source(ORG, {"source_name": "Dup Test"})
    tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "11.11.11.11", "threat_category": "c2"})
    result = tip_engine.bulk_ingest(ORG, src["id"], [
        {"indicator_type": "ip", "value": "11.11.11.11", "threat_category": "c2"},
        {"indicator_type": "ip", "value": "22.22.22.22", "threat_category": "apt"},
    ])
    assert result["added"] == 1
    assert result["duplicates"] == 1


def test_bulk_ingest_with_errors(tip_engine):
    src = tip_engine.add_source(ORG, {"source_name": "Err Test"})
    result = tip_engine.bulk_ingest(ORG, src["id"], [
        {"indicator_type": "ip", "value": "1.2.3.4", "threat_category": "malware"},
        {"indicator_type": "INVALID_TYPE", "value": "something"},  # should error
    ])
    assert result["added"] == 1
    assert result["errors"] == 1


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------

def test_add_relationship(tip_engine):
    a = tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "3.3.3.3", "threat_category": "c2"})
    b = tip_engine.add_indicator(ORG, {"indicator_type": "domain", "value": "c2.evil.com", "threat_category": "c2"})
    rel = tip_engine.add_relationship(ORG, {
        "indicator_a_id": a["id"],
        "indicator_b_id": b["id"],
        "relationship_type": "resolves_to",
        "confidence": 0.9,
    })
    assert rel["id"]
    assert rel["relationship_type"] == "resolves_to"


def test_get_relationships(tip_engine):
    a = tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "4.4.4.4", "threat_category": "botnet"})
    b = tip_engine.add_indicator(ORG, {"indicator_type": "url", "value": "http://bad.com/c2", "threat_category": "c2"})
    tip_engine.add_relationship(ORG, {
        "indicator_a_id": a["id"],
        "indicator_b_id": b["id"],
        "relationship_type": "communicates_with",
    })
    rels = tip_engine.get_relationships(ORG, a["id"])
    assert len(rels) == 1
    assert rels[0]["relationship_type"] == "communicates_with"


def test_add_relationship_invalid_type(tip_engine):
    with pytest.raises(ValueError):
        tip_engine.add_relationship(ORG, {
            "indicator_a_id": "a", "indicator_b_id": "b", "relationship_type": "hacks"
        })


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def test_create_report(tip_engine):
    report = tip_engine.create_report(ORG, {
        "report_name": "APT28 Flash Report",
        "report_type": "flash",
        "classification": "confidential",
        "tlp_level": "amber",
        "summary": "APT28 targeting energy sector.",
        "ioc_count": 15,
        "threat_actors": ["APT28", "Fancy Bear"],
        "affected_sectors": ["energy", "government"],
    })
    assert report["id"]
    assert report["report_name"] == "APT28 Flash Report"
    assert isinstance(report["threat_actors"], list)


def test_list_reports_filtered(tip_engine):
    tip_engine.create_report(ORG, {"report_name": "Flash 1", "report_type": "flash"})
    tip_engine.create_report(ORG, {"report_name": "Strategic 1", "report_type": "strategic"})
    flash_reports = tip_engine.list_reports(ORG, report_type="flash")
    assert all(r["report_type"] == "flash" for r in flash_reports)


def test_create_report_missing_name(tip_engine):
    with pytest.raises(ValueError, match="report_name"):
        tip_engine.create_report(ORG, {"report_type": "flash"})


# ---------------------------------------------------------------------------
# Check indicator
# ---------------------------------------------------------------------------

def test_check_indicator_known_bad(tip_engine):
    tip_engine.add_indicator(ORG, {
        "indicator_type": "ip", "value": "6.6.6.6", "severity": "critical", "threat_category": "apt"
    })
    result = tip_engine.check_indicator(ORG, "6.6.6.6", "ip")
    assert result["known_bad"] is True
    assert result["indicator"] is not None


def test_check_indicator_clean(tip_engine):
    result = tip_engine.check_indicator(ORG, "8.8.8.8", "ip")
    assert result["known_bad"] is False
    assert result["indicator"] is None


def test_check_indicator_wrong_org(tip_engine):
    tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "5.6.7.8", "threat_category": "c2"})
    result = tip_engine.check_indicator(ORG2, "5.6.7.8", "ip")
    assert result["known_bad"] is False


# ---------------------------------------------------------------------------
# Expire + Stats
# ---------------------------------------------------------------------------

def test_expire_indicators(tip_engine):
    tip_engine.add_indicator(ORG, {
        "indicator_type": "ip", "value": "99.99.99.99",
        "threat_category": "botnet",
        "expiry_date": "2000-01-01T00:00:00+00:00",  # already expired
    })
    expired = tip_engine.expire_indicators(ORG)
    assert expired == 1
    result = tip_engine.check_indicator(ORG, "99.99.99.99", "ip")
    assert result["known_bad"] is False


def test_get_tip_stats(tip_engine):
    tip_engine.add_indicator(ORG, {"indicator_type": "ip", "value": "100.100.100.1", "threat_category": "malware", "severity": "high"})
    tip_engine.add_indicator(ORG, {"indicator_type": "domain", "value": "abc.evil.com", "threat_category": "phishing", "severity": "medium"})
    tip_engine.add_source(ORG, {"source_name": "StatsSource"})
    stats = tip_engine.get_tip_stats(ORG)
    assert stats["total_indicators"] >= 2
    assert stats["active_indicators"] >= 2
    assert stats["sources_active"] >= 1
    assert "by_type" in stats
    assert "by_category" in stats
    assert "by_severity" in stats
    assert "top_threat_categories" in stats
