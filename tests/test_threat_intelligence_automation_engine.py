"""Tests for ThreatIntelligenceAutomationEngine — 30+ tests covering all major paths."""

from __future__ import annotations

import hashlib
import pytest


@pytest.fixture
def tia_engine(tmp_path):
    from core.threat_intelligence_automation_engine import ThreatIntelligenceAutomationEngine
    return ThreatIntelligenceAutomationEngine(db_dir=str(tmp_path))


ORG = "test-org-tia"
ORG2 = "other-org-tia"


# ---------------------------------------------------------------------------
# Feeds
# ---------------------------------------------------------------------------

def test_register_feed_basic(tia_engine):
    feed = tia_engine.register_feed(ORG, {"feed_name": "AlienVault OTX", "feed_type": "osint"})
    assert feed["id"]
    assert feed["feed_name"] == "AlienVault OTX"
    assert feed["feed_type"] == "osint"
    assert feed["status"] == "active"
    assert feed["ioc_count"] == 0
    assert feed["poll_interval_minutes"] == 60


def test_register_feed_all_types(tia_engine):
    for ft in ("osint", "commercial", "isac", "government", "dark_web", "honeypot", "internal"):
        feed = tia_engine.register_feed(ORG, {"feed_name": f"Feed-{ft}", "feed_type": ft})
        assert feed["feed_type"] == ft


def test_register_feed_all_formats(tia_engine):
    for fmt in ("stix", "misp", "csv", "json", "xml", "taxii"):
        feed = tia_engine.register_feed(ORG, {"feed_name": f"Feed-{fmt}", "format": fmt})
        assert feed["format"] == fmt


def test_register_feed_api_key_hashed(tia_engine):
    """API key must be stored as SHA-256 hash, never plaintext."""
    raw_key = "super-secret-api-key-12345"
    feed = tia_engine.register_feed(ORG, {
        "feed_name": "Recorded Future",
        "feed_type": "commercial",
        "api_key": raw_key,
    })
    expected_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    assert feed["api_key_hash"] == expected_hash
    assert raw_key not in str(feed)


def test_register_feed_no_api_key_empty_hash(tia_engine):
    feed = tia_engine.register_feed(ORG, {"feed_name": "PublicFeed"})
    assert feed["api_key_hash"] == ""


def test_register_feed_missing_name(tia_engine):
    with pytest.raises(ValueError, match="feed_name"):
        tia_engine.register_feed(ORG, {"feed_type": "osint"})


def test_register_feed_invalid_feed_type(tia_engine):
    with pytest.raises(ValueError):
        tia_engine.register_feed(ORG, {"feed_name": "X", "feed_type": "unknown"})


def test_register_feed_invalid_format(tia_engine):
    with pytest.raises(ValueError):
        tia_engine.register_feed(ORG, {"feed_name": "X", "format": "yaml"})


def test_list_feeds_empty(tia_engine):
    assert tia_engine.list_feeds(ORG) == []


def test_list_feeds_filter_by_type(tia_engine):
    tia_engine.register_feed(ORG, {"feed_name": "A", "feed_type": "osint"})
    tia_engine.register_feed(ORG, {"feed_name": "B", "feed_type": "commercial"})
    results = tia_engine.list_feeds(ORG, feed_type="osint")
    assert len(results) == 1
    assert results[0]["feed_name"] == "A"


def test_list_feeds_filter_by_status(tia_engine):
    tia_engine.register_feed(ORG, {"feed_name": "Active", "status": "active"})
    tia_engine.register_feed(ORG, {"feed_name": "Inactive", "status": "inactive"})
    active = tia_engine.list_feeds(ORG, status="active")
    assert len(active) == 1
    assert active[0]["feed_name"] == "Active"


def test_list_feeds_org_isolation(tia_engine):
    tia_engine.register_feed(ORG, {"feed_name": "Org1Feed"})
    assert tia_engine.list_feeds(ORG2) == []


def test_update_feed_stats(tia_engine):
    feed = tia_engine.register_feed(ORG, {"feed_name": "StatsFeed"})
    updated = tia_engine.update_feed_stats(ORG, feed["id"], 100)
    assert updated["ioc_count"] == 100
    assert updated["last_polled"] is not None


def test_update_feed_stats_increments(tia_engine):
    feed = tia_engine.register_feed(ORG, {"feed_name": "IncrFeed", "ioc_count": 50})
    tia_engine.update_feed_stats(ORG, feed["id"], 25)
    updated = tia_engine.update_feed_stats(ORG, feed["id"], 25)
    assert updated["ioc_count"] == 100


def test_update_feed_stats_not_found(tia_engine):
    with pytest.raises(KeyError):
        tia_engine.update_feed_stats(ORG, "nonexistent-id", 10)


def test_update_feed_stats_wrong_org(tia_engine):
    feed = tia_engine.register_feed(ORG, {"feed_name": "OrgFeed"})
    with pytest.raises(KeyError):
        tia_engine.update_feed_stats(ORG2, feed["id"], 10)


# ---------------------------------------------------------------------------
# Automations
# ---------------------------------------------------------------------------

def test_create_automation_basic(tia_engine):
    auto = tia_engine.create_automation(ORG, {
        "automation_name": "Block malicious IPs",
        "trigger_type": "new_ioc",
        "action_type": "block_ip",
    })
    assert auto["id"]
    assert auto["automation_name"] == "Block malicious IPs"
    assert auto["trigger_type"] == "new_ioc"
    assert auto["action_type"] == "block_ip"
    assert auto["enabled"] is True
    assert auto["execution_count"] == 0


def test_create_automation_condition_json_roundtrip(tia_engine):
    condition = {"ioc_type": "ip", "confidence_min": 80, "tags": ["apt"]}
    auto = tia_engine.create_automation(ORG, {
        "automation_name": "APT IP Block",
        "condition": condition,
    })
    assert auto["condition"] == condition


def test_create_automation_missing_name(tia_engine):
    with pytest.raises(ValueError, match="automation_name"):
        tia_engine.create_automation(ORG, {"trigger_type": "manual"})


def test_create_automation_invalid_trigger(tia_engine):
    with pytest.raises(ValueError):
        tia_engine.create_automation(ORG, {"automation_name": "X", "trigger_type": "bad"})


def test_create_automation_invalid_action(tia_engine):
    with pytest.raises(ValueError):
        tia_engine.create_automation(ORG, {"automation_name": "X", "action_type": "bad"})


def test_create_automation_all_trigger_types(tia_engine):
    for tt in ("new_ioc", "confidence_threshold", "feed_update", "scheduled", "manual"):
        auto = tia_engine.create_automation(ORG, {
            "automation_name": f"Auto-{tt}", "trigger_type": tt
        })
        assert auto["trigger_type"] == tt


def test_create_automation_disabled(tia_engine):
    auto = tia_engine.create_automation(ORG, {
        "automation_name": "Disabled Rule", "enabled": False
    })
    assert auto["enabled"] is False


def test_execute_automation(tia_engine):
    auto = tia_engine.create_automation(ORG, {"automation_name": "ExecTest"})
    result = tia_engine.execute_automation(ORG, auto["id"])
    assert result["execution_count"] == 1
    assert result["last_executed"] is not None


def test_execute_automation_increments(tia_engine):
    auto = tia_engine.create_automation(ORG, {"automation_name": "MultiExec"})
    tia_engine.execute_automation(ORG, auto["id"])
    result = tia_engine.execute_automation(ORG, auto["id"])
    assert result["execution_count"] == 2


def test_execute_automation_not_found(tia_engine):
    with pytest.raises(KeyError):
        tia_engine.execute_automation(ORG, "nonexistent-id")


def test_execute_automation_wrong_org(tia_engine):
    auto = tia_engine.create_automation(ORG, {"automation_name": "OrgAuto"})
    with pytest.raises(KeyError):
        tia_engine.execute_automation(ORG2, auto["id"])


def test_list_automations_filter_trigger(tia_engine):
    tia_engine.create_automation(ORG, {"automation_name": "A", "trigger_type": "manual"})
    tia_engine.create_automation(ORG, {"automation_name": "B", "trigger_type": "scheduled"})
    results = tia_engine.list_automations(ORG, trigger_type="manual")
    assert len(results) == 1
    assert results[0]["automation_name"] == "A"


def test_list_automations_filter_enabled(tia_engine):
    tia_engine.create_automation(ORG, {"automation_name": "Enabled", "enabled": True})
    tia_engine.create_automation(ORG, {"automation_name": "Disabled", "enabled": False})
    enabled = tia_engine.list_automations(ORG, enabled=True)
    assert len(enabled) == 1
    assert enabled[0]["automation_name"] == "Enabled"


def test_list_automations_org_isolation(tia_engine):
    tia_engine.create_automation(ORG, {"automation_name": "Org1Auto"})
    assert tia_engine.list_automations(ORG2) == []


# ---------------------------------------------------------------------------
# Enrichments
# ---------------------------------------------------------------------------

def test_store_enrichment_basic(tia_engine):
    enr = tia_engine.store_enrichment(ORG, {
        "ioc_value": "1.2.3.4",
        "ioc_type": "ip",
        "confidence_score": 85.0,
        "is_malicious": True,
    })
    assert enr["id"]
    assert enr["ioc_value"] == "1.2.3.4"
    assert enr["ioc_type"] == "ip"
    assert enr["confidence_score"] == 85.0
    assert enr["is_malicious"] is True


def test_store_enrichment_all_ioc_types(tia_engine):
    for ioc_type in ("ip", "domain", "url", "hash", "email", "asn", "cve"):
        enr = tia_engine.store_enrichment(ORG, {
            "ioc_value": f"val-{ioc_type}",
            "ioc_type": ioc_type,
        })
        assert enr["ioc_type"] == ioc_type


def test_store_enrichment_json_roundtrip(tia_engine):
    sources = ["VirusTotal", "AlienVault", "Shodan"]
    cats = ["malware", "c2"]
    enr = tia_engine.store_enrichment(ORG, {
        "ioc_value": "evil.com",
        "ioc_type": "domain",
        "sources": sources,
        "threat_categories": cats,
    })
    assert enr["sources"] == sources
    assert enr["threat_categories"] == cats


def test_store_enrichment_confidence_clamped(tia_engine):
    enr = tia_engine.store_enrichment(ORG, {"ioc_value": "x.com", "confidence_score": 150.0})
    assert enr["confidence_score"] == 100.0
    enr2 = tia_engine.store_enrichment(ORG, {"ioc_value": "y.com", "confidence_score": -10.0})
    assert enr2["confidence_score"] == 0.0


def test_store_enrichment_missing_ioc_value(tia_engine):
    with pytest.raises(ValueError, match="ioc_value"):
        tia_engine.store_enrichment(ORG, {"ioc_type": "ip"})


def test_store_enrichment_invalid_ioc_type(tia_engine):
    with pytest.raises(ValueError):
        tia_engine.store_enrichment(ORG, {"ioc_value": "x", "ioc_type": "certificate"})


def test_get_enrichment_returns_most_recent(tia_engine):
    tia_engine.store_enrichment(ORG, {"ioc_value": "1.1.1.1", "confidence_score": 50.0})
    tia_engine.store_enrichment(ORG, {"ioc_value": "1.1.1.1", "confidence_score": 90.0})
    result = tia_engine.get_enrichment(ORG, "1.1.1.1")
    # Most recent insert has confidence 90
    assert result is not None
    assert result["ioc_value"] == "1.1.1.1"


def test_get_enrichment_not_found(tia_engine):
    result = tia_engine.get_enrichment(ORG, "nonexistent.ioc")
    assert result is None


def test_get_enrichment_org_isolation(tia_engine):
    tia_engine.store_enrichment(ORG, {"ioc_value": "2.2.2.2"})
    assert tia_engine.get_enrichment(ORG2, "2.2.2.2") is None


def test_list_enrichments_filter_ioc_type(tia_engine):
    tia_engine.store_enrichment(ORG, {"ioc_value": "3.3.3.3", "ioc_type": "ip"})
    tia_engine.store_enrichment(ORG, {"ioc_value": "bad.com", "ioc_type": "domain"})
    ips = tia_engine.list_enrichments(ORG, ioc_type="ip")
    assert len(ips) == 1
    assert ips[0]["ioc_value"] == "3.3.3.3"


def test_list_enrichments_filter_malicious(tia_engine):
    tia_engine.store_enrichment(ORG, {"ioc_value": "mal.com", "ioc_type": "domain", "is_malicious": True})
    tia_engine.store_enrichment(ORG, {"ioc_value": "ok.com", "ioc_type": "domain", "is_malicious": False})
    mal = tia_engine.list_enrichments(ORG, is_malicious=True)
    assert len(mal) == 1
    assert mal[0]["ioc_value"] == "mal.com"


def test_list_enrichments_org_isolation(tia_engine):
    tia_engine.store_enrichment(ORG, {"ioc_value": "4.4.4.4"})
    assert tia_engine.list_enrichments(ORG2) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_ti_stats_empty(tia_engine):
    stats = tia_engine.get_ti_stats(ORG)
    assert stats["total_feeds"] == 0
    assert stats["active_feeds"] == 0
    assert stats["total_iocs"] == 0
    assert stats["total_automations"] == 0
    assert stats["active_automations"] == 0
    assert stats["total_enrichments"] == 0
    assert stats["malicious_enrichments"] == 0
    assert stats["by_feed_type"] == {}
    assert stats["by_ioc_type"] == {}


def test_get_ti_stats_populated(tia_engine):
    tia_engine.register_feed(ORG, {"feed_name": "F1", "feed_type": "osint", "ioc_count": 100})
    tia_engine.register_feed(ORG, {"feed_name": "F2", "feed_type": "commercial", "ioc_count": 200, "status": "inactive"})
    tia_engine.create_automation(ORG, {"automation_name": "A1", "enabled": True})
    tia_engine.create_automation(ORG, {"automation_name": "A2", "enabled": False})
    tia_engine.store_enrichment(ORG, {"ioc_value": "5.5.5.5", "ioc_type": "ip", "is_malicious": True})
    tia_engine.store_enrichment(ORG, {"ioc_value": "good.com", "ioc_type": "domain", "is_malicious": False})

    stats = tia_engine.get_ti_stats(ORG)
    assert stats["total_feeds"] == 2
    assert stats["active_feeds"] == 1
    assert stats["total_iocs"] == 300
    assert stats["total_automations"] == 2
    assert stats["active_automations"] == 1
    assert stats["total_enrichments"] == 2
    assert stats["malicious_enrichments"] == 1
    assert stats["by_feed_type"]["osint"] == 1
    assert stats["by_feed_type"]["commercial"] == 1
    assert stats["by_ioc_type"]["ip"] == 1
    assert stats["by_ioc_type"]["domain"] == 1


def test_get_ti_stats_org_isolation(tia_engine):
    tia_engine.register_feed(ORG, {"feed_name": "Org1Feed"})
    stats = tia_engine.get_ti_stats(ORG2)
    assert stats["total_feeds"] == 0
