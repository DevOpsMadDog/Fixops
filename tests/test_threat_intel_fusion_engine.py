"""Tests for ThreatIntelFusionEngine — 30+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def engine(tmp_path):
    from core.threat_intel_fusion_engine import ThreatIntelFusionEngine
    return ThreatIntelFusionEngine(db_path=str(tmp_path / "fusion.db"))


ORG = "test-org-fusion"
ORG2 = "other-org-fusion"


# ---------------------------------------------------------------------------
# Intel sources
# ---------------------------------------------------------------------------

def test_add_source_basic(engine):
    src = engine.add_intel_source(ORG, {"name": "AlienVault OTX", "source_type": "osint"})
    assert src["id"]
    assert src["name"] == "AlienVault OTX"
    assert src["source_type"] == "osint"
    assert src["enabled"] is True


def test_add_source_all_fields(engine):
    src = engine.add_intel_source(ORG, {
        "name": "Recorded Future",
        "source_type": "commercial",
        "reliability": 9,
        "tlp_level": "amber",
    })
    assert src["source_type"] == "commercial"
    assert src["reliability"] == 9
    assert src["tlp_level"] == "amber"


def test_add_source_missing_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.add_intel_source(ORG, {"source_type": "osint"})


def test_add_source_invalid_type(engine):
    with pytest.raises(ValueError, match="source_type"):
        engine.add_intel_source(ORG, {"name": "X", "source_type": "unknown"})


def test_add_source_invalid_tlp(engine):
    with pytest.raises(ValueError, match="tlp_level"):
        engine.add_intel_source(ORG, {"name": "X", "tlp_level": "purple"})


def test_add_source_reliability_clamped(engine):
    src = engine.add_intel_source(ORG, {"name": "X", "reliability": 99})
    assert src["reliability"] == 10
    src2 = engine.add_intel_source(ORG, {"name": "Y", "reliability": -5})
    assert src2["reliability"] == 1


def test_list_sources_empty(engine):
    assert engine.list_intel_sources(ORG) == []


def test_list_sources_returns_added(engine):
    engine.add_intel_source(ORG, {"name": "Source A", "source_type": "isac"})
    sources = engine.list_intel_sources(ORG)
    assert len(sources) == 1
    assert sources[0]["name"] == "Source A"


def test_list_sources_org_isolation(engine):
    engine.add_intel_source(ORG, {"name": "Source A"})
    assert engine.list_intel_sources(ORG2) == []


def test_add_source_all_types(engine):
    for st in ("osint", "commercial", "isac", "internal", "government"):
        src = engine.add_intel_source(ORG, {"name": f"Src-{st}", "source_type": st})
        assert src["source_type"] == st


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

def test_ingest_indicator_basic(engine):
    ind = engine.ingest_indicator(ORG, {
        "indicator_type": "ip",
        "value": "1.2.3.4",
        "confidence": 75,
    })
    assert ind["id"]
    assert ind["indicator_type"] == "ip"
    assert ind["value"] == "1.2.3.4"
    assert ind["confidence"] == 75
    assert ind["status"] == "active"


def test_ingest_indicator_all_fields(engine):
    ind = engine.ingest_indicator(ORG, {
        "source_id": "src-001",
        "indicator_type": "domain",
        "value": "evil.example.com",
        "confidence": 90,
        "tags": ["phishing", "apt"],
        "expiry_days": 7,
    })
    assert ind["source_id"] == "src-001"
    assert ind["tags"] == ["phishing", "apt"]
    assert ind["expiry_date"] is not None


def test_ingest_indicator_missing_value(engine):
    with pytest.raises(ValueError, match="value"):
        engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": ""})


def test_ingest_indicator_invalid_type(engine):
    with pytest.raises(ValueError, match="indicator_type"):
        engine.ingest_indicator(ORG, {"indicator_type": "asn", "value": "AS12345"})


def test_ingest_indicator_confidence_clamped(engine):
    ind_high = engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "9.9.9.9", "confidence": 200})
    assert ind_high["confidence"] == 100
    ind_low = engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "8.8.8.8", "confidence": -10})
    assert ind_low["confidence"] == 0


def test_ingest_indicator_all_types(engine):
    for itype in ("ip", "domain", "hash", "url", "email"):
        ind = engine.ingest_indicator(ORG, {"indicator_type": itype, "value": f"test-{itype}"})
        assert ind["indicator_type"] == itype


# ---------------------------------------------------------------------------
# Search indicators
# ---------------------------------------------------------------------------

def test_search_indicators_by_value(engine):
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "192.168.1.100"})
    engine.ingest_indicator(ORG, {"indicator_type": "domain", "value": "evil.com"})
    result = engine.search_indicators(ORG, "192.168")
    assert len(result) == 1
    assert result[0]["value"] == "192.168.1.100"


def test_search_indicators_filter_type(engine):
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "10.0.0.1"})
    engine.ingest_indicator(ORG, {"indicator_type": "domain", "value": "10.evil.com"})
    result = engine.search_indicators(ORG, "10", indicator_type="ip")
    assert all(r["indicator_type"] == "ip" for r in result)


def test_search_indicators_empty(engine):
    result = engine.search_indicators(ORG, "nomatch")
    assert result == []


def test_search_indicators_org_isolation(engine):
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "1.1.1.1"})
    result = engine.search_indicators(ORG2, "1.1.1.1")
    assert result == []


# ---------------------------------------------------------------------------
# Fuse indicator
# ---------------------------------------------------------------------------

def test_fuse_indicator_not_found(engine):
    result = engine.fuse_indicator(ORG, "notexist.com")
    assert result["found"] is False
    assert result["consensus_confidence"] == 0
    assert result["source_count"] == 0


def test_fuse_indicator_single_source(engine):
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "5.5.5.5", "confidence": 80})
    result = engine.fuse_indicator(ORG, "5.5.5.5")
    assert result["found"] is True
    assert result["consensus_confidence"] == 80
    assert result["source_count"] == 1
    assert len(result["records"]) == 1


def test_fuse_indicator_multiple_sources(engine):
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "6.6.6.6", "confidence": 60})
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "6.6.6.6", "confidence": 80})
    engine.ingest_indicator(ORG, {"indicator_type": "domain", "value": "6.6.6.6", "confidence": 100})
    result = engine.fuse_indicator(ORG, "6.6.6.6")
    assert result["found"] is True
    assert result["source_count"] == 3
    assert result["consensus_confidence"] == 80  # avg(60+80+100)/3


def test_fuse_indicator_org_isolation(engine):
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "7.7.7.7", "confidence": 90})
    result = engine.fuse_indicator(ORG2, "7.7.7.7")
    assert result["found"] is False


# ---------------------------------------------------------------------------
# High confidence indicators
# ---------------------------------------------------------------------------

def test_get_high_confidence_empty(engine):
    result = engine.get_high_confidence_indicators(ORG)
    assert result == []


def test_get_high_confidence_filters(engine):
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "10.1.1.1", "confidence": 90})
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "10.1.1.2", "confidence": 50})
    result = engine.get_high_confidence_indicators(ORG, min_confidence=80)
    assert len(result) == 1
    assert result[0]["value"] == "10.1.1.1"


def test_get_high_confidence_limit(engine):
    for i in range(5):
        engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": f"11.0.0.{i}", "confidence": 95})
    result = engine.get_high_confidence_indicators(ORG, min_confidence=80, limit=3)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# Expire indicators
# ---------------------------------------------------------------------------

def test_expire_no_expired(engine):
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "20.0.0.1", "confidence": 70, "expiry_days": 30})
    result = engine.expire_old_indicators(ORG)
    assert result["expired"] == 0


def test_expire_returns_summary(engine):
    result = engine.expire_old_indicators(ORG)
    assert "expired" in result
    assert "timestamp" in result
    assert result["org_id"] == ORG


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine):
    stats = engine.get_fusion_stats(ORG)
    assert stats["org_id"] == ORG
    assert stats["sources"] == 0
    assert stats["total_indicators"] == 0
    assert stats["high_confidence"] == 0
    assert stats["expired"] == 0
    assert stats["by_type"] == {}


def test_get_stats_populated(engine):
    engine.add_intel_source(ORG, {"name": "Src A", "source_type": "osint"})
    engine.add_intel_source(ORG, {"name": "Src B", "source_type": "isac"})
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "1.1.1.1", "confidence": 90})
    engine.ingest_indicator(ORG, {"indicator_type": "domain", "value": "bad.com", "confidence": 50})
    engine.ingest_indicator(ORG, {"indicator_type": "ip", "value": "2.2.2.2", "confidence": 85})
    stats = engine.get_fusion_stats(ORG)
    assert stats["sources"] == 2
    assert stats["total_indicators"] == 3
    assert stats["high_confidence"] == 2
    assert stats["by_type"]["ip"] == 2
    assert stats["by_type"]["domain"] == 1


def test_get_stats_org_isolation(engine):
    engine.add_intel_source(ORG, {"name": "Source"})
    stats = engine.get_fusion_stats(ORG2)
    assert stats["sources"] == 0
    assert stats["total_indicators"] == 0
