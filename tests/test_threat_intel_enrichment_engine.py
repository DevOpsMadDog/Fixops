"""Tests for ThreatIntelEnrichmentEngine — 35+ tests."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.threat_intel_enrichment_engine import ThreatIntelEnrichmentEngine

ORG = "test-org"
OTHER_ORG = "other-org"


@pytest.fixture
def engine(tmp_path):
    return ThreatIntelEnrichmentEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# create_enrichment_request
# ---------------------------------------------------------------------------

def test_create_request_basic(engine):
    req = engine.create_enrichment_request(ORG, "8.8.8.8", "ip")
    assert req["id"]
    assert req["org_id"] == ORG
    assert req["indicator"] == "8.8.8.8"
    assert req["indicator_type"] == "ip"
    assert req["status"] == "pending"
    assert req["sources_queried"] == 0
    assert req["sources_responded"] == 0
    assert req["completed_at"] is None


def test_create_request_all_indicator_types(engine):
    types = ["ip", "domain", "url", "hash", "email", "cve", "asn", "certificate"]
    for t in types:
        req = engine.create_enrichment_request(ORG, f"test-{t}", t)
        assert req["indicator_type"] == t


def test_create_request_invalid_type(engine):
    with pytest.raises(ValueError, match="indicator_type"):
        engine.create_enrichment_request(ORG, "bad", "invalid_type")


def test_create_request_empty_indicator(engine):
    with pytest.raises(ValueError, match="indicator"):
        engine.create_enrichment_request(ORG, "", "ip")


def test_create_request_with_sources_queried(engine):
    req = engine.create_enrichment_request(ORG, "evil.com", "domain", sources_queried=3)
    assert req["sources_queried"] == 3


# ---------------------------------------------------------------------------
# add_enrichment_result
# ---------------------------------------------------------------------------

def test_add_result_basic(engine):
    req = engine.create_enrichment_request(ORG, "192.168.1.1", "ip", sources_queried=2)
    result = engine.add_enrichment_result(
        request_id=req["id"],
        org_id=ORG,
        source="VirusTotal",
        reputation_score=75.0,
        malicious=True,
        tags=["malware", "c2"],
        context="Known C2 server",
        confidence=0.9,
    )
    assert result["source"] == "VirusTotal"
    assert result["reputation_score"] == 75.0
    assert result["malicious"] == 1
    assert result["confidence"] == 0.9


def test_add_result_increments_sources_responded(engine):
    req = engine.create_enrichment_request(ORG, "10.0.0.1", "ip", sources_queried=3)
    for i in range(2):
        engine.add_enrichment_result(req["id"], ORG, f"src{i}", 50.0, False, [], "", 0.5)
    enrichment = engine.get_enrichment(req["id"], ORG)
    assert enrichment["sources_responded"] == 2
    assert enrichment["status"] == "pending"  # not yet >= 3


def test_add_result_auto_completes_when_all_responded(engine):
    req = engine.create_enrichment_request(ORG, "example.com", "domain", sources_queried=2)
    engine.add_enrichment_result(req["id"], ORG, "src1", 10.0, False, [], "", 0.5)
    engine.add_enrichment_result(req["id"], ORG, "src2", 20.0, False, [], "", 0.6)
    enrichment = engine.get_enrichment(req["id"], ORG)
    assert enrichment["status"] == "completed"
    assert enrichment["completed_at"] is not None


def test_add_result_confidence_clamped_above_1(engine):
    req = engine.create_enrichment_request(ORG, "test.com", "domain")
    result = engine.add_enrichment_result(req["id"], ORG, "src", 50.0, False, [], "", 1.5)
    assert result["confidence"] == 1.0


def test_add_result_confidence_clamped_below_0(engine):
    req = engine.create_enrichment_request(ORG, "test.com", "domain")
    result = engine.add_enrichment_result(req["id"], ORG, "src", 50.0, False, [], "", -0.5)
    assert result["confidence"] == 0.0


def test_add_result_reputation_clamped_above_100(engine):
    req = engine.create_enrichment_request(ORG, "test.com", "domain")
    result = engine.add_enrichment_result(req["id"], ORG, "src", 150.0, True, [], "", 0.8)
    assert result["reputation_score"] == 100.0


def test_add_result_reputation_clamped_below_0(engine):
    req = engine.create_enrichment_request(ORG, "test.com", "domain")
    result = engine.add_enrichment_result(req["id"], ORG, "src", -10.0, False, [], "", 0.5)
    assert result["reputation_score"] == 0.0


def test_add_result_empty_source_raises(engine):
    req = engine.create_enrichment_request(ORG, "test.com", "domain")
    with pytest.raises(ValueError, match="source"):
        engine.add_enrichment_result(req["id"], ORG, "", 50.0, False, [], "", 0.5)


# ---------------------------------------------------------------------------
# get_enrichment
# ---------------------------------------------------------------------------

def test_get_enrichment_with_results(engine):
    req = engine.create_enrichment_request(ORG, "bad.com", "domain", sources_queried=1)
    engine.add_enrichment_result(req["id"], ORG, "OTX", 80.0, True, ["phishing"], "Phishing site", 0.85)
    enrichment = engine.get_enrichment(req["id"], ORG)
    assert enrichment["indicator"] == "bad.com"
    assert len(enrichment["results"]) == 1
    result = enrichment["results"][0]
    assert result["tags"] == ["phishing"]


def test_get_enrichment_not_found(engine):
    assert engine.get_enrichment("nonexistent", ORG) is None


def test_get_enrichment_org_isolation(engine):
    req = engine.create_enrichment_request(ORG, "test.com", "domain")
    assert engine.get_enrichment(req["id"], OTHER_ORG) is None


# ---------------------------------------------------------------------------
# get_indicator_summary
# ---------------------------------------------------------------------------

def test_indicator_summary_malicious_aggregation(engine):
    req1 = engine.create_enrichment_request(ORG, "evil.com", "domain")
    req2 = engine.create_enrichment_request(ORG, "evil.com", "domain")
    engine.add_enrichment_result(req1["id"], ORG, "src1", 70.0, False, ["spam"], "", 0.6)
    engine.add_enrichment_result(req2["id"], ORG, "src2", 90.0, True, ["malware"], "", 0.9)
    summary = engine.get_indicator_summary(ORG, "evil.com")
    assert summary["malicious"] is True  # any malicious → True
    assert set(summary["combined_tags"]) == {"spam", "malware"}
    assert summary["max_confidence"] == 0.9


def test_indicator_summary_avg_reputation(engine):
    req = engine.create_enrichment_request(ORG, "test.com", "domain")
    engine.add_enrichment_result(req["id"], ORG, "src1", 40.0, False, [], "", 0.5)
    engine.add_enrichment_result(req["id"], ORG, "src2", 60.0, False, [], "", 0.7)
    summary = engine.get_indicator_summary(ORG, "test.com")
    assert summary["avg_reputation_score"] == pytest.approx(50.0)


def test_indicator_summary_not_found(engine):
    summary = engine.get_indicator_summary(ORG, "unknown.com")
    assert summary["avg_reputation_score"] is None
    assert summary["malicious"] is False
    assert summary["combined_tags"] == []


# ---------------------------------------------------------------------------
# register_source
# ---------------------------------------------------------------------------

def test_register_source_basic(engine):
    src = engine.register_source(ORG, "VirusTotal", "commercial", "my-api-key")
    assert src["source_name"] == "VirusTotal"
    assert src["source_type"] == "commercial"
    assert src["enabled"] == 1
    assert len(src["api_key_hash"]) == 64  # SHA-256
    assert src["request_count"] == 0
    assert src["success_rate"] == 0.0


def test_register_source_api_key_is_hashed(engine):
    src = engine.register_source(ORG, "OTX", "open-source", "secret123")
    # Must not contain the raw key
    assert "secret123" not in str(src.values())
    assert len(src["api_key_hash"]) == 64


def test_register_source_all_types(engine):
    types = ["commercial", "open-source", "isac", "internal", "government", "community"]
    for t in types:
        src = engine.register_source(ORG, f"src-{t}", t)
        assert src["source_type"] == t


def test_register_source_invalid_type(engine):
    with pytest.raises(ValueError, match="source_type"):
        engine.register_source(ORG, "Bad", "invalid")


def test_register_source_empty_name(engine):
    with pytest.raises(ValueError, match="source_name"):
        engine.register_source(ORG, "", "commercial")


# ---------------------------------------------------------------------------
# update_source_stats
# ---------------------------------------------------------------------------

def test_update_source_stats_success(engine):
    src = engine.register_source(ORG, "VT", "commercial")
    updated = engine.update_source_stats(src["id"], ORG, success=True)
    assert updated["request_count"] == 1
    assert updated["success_rate"] == 1.0


def test_update_source_stats_failure(engine):
    src = engine.register_source(ORG, "VT", "commercial")
    updated = engine.update_source_stats(src["id"], ORG, success=False)
    assert updated["request_count"] == 1
    assert updated["success_rate"] == 0.0


def test_update_source_stats_running_average(engine):
    src = engine.register_source(ORG, "VT", "commercial")
    engine.update_source_stats(src["id"], ORG, success=True)
    engine.update_source_stats(src["id"], ORG, success=True)
    updated = engine.update_source_stats(src["id"], ORG, success=False)
    assert updated["request_count"] == 3
    assert updated["success_rate"] == pytest.approx(2 / 3, rel=0.01)


def test_update_source_stats_not_found(engine):
    with pytest.raises(KeyError):
        engine.update_source_stats("nonexistent", ORG, success=True)


# ---------------------------------------------------------------------------
# list_sources
# ---------------------------------------------------------------------------

def test_list_sources_all(engine):
    engine.register_source(ORG, "src1", "commercial")
    engine.register_source(ORG, "src2", "internal")
    sources = engine.list_sources(ORG)
    assert len(sources) == 2


def test_list_sources_enabled_filter(engine):
    src = engine.register_source(ORG, "src1", "commercial")
    engine.register_source(ORG, "src2", "internal")
    enabled = engine.list_sources(ORG, enabled=True)
    assert len(enabled) == 2  # both enabled by default


def test_list_sources_org_isolation(engine):
    engine.register_source(ORG, "src1", "commercial")
    engine.register_source(OTHER_ORG, "src2", "commercial")
    sources = engine.list_sources(ORG)
    assert len(sources) == 1


# ---------------------------------------------------------------------------
# get_enrichment_stats
# ---------------------------------------------------------------------------

def test_get_enrichment_stats_empty(engine):
    stats = engine.get_enrichment_stats(ORG)
    assert stats["total_requests"] == 0
    assert stats["completed"] == 0
    assert stats["pending"] == 0


def test_get_enrichment_stats_with_data(engine):
    req1 = engine.create_enrichment_request(ORG, "a.com", "domain", sources_queried=1)
    engine.add_enrichment_result(req1["id"], ORG, "src", 80.0, True, [], "", 0.9)
    req2 = engine.create_enrichment_request(ORG, "b.com", "domain")
    stats = engine.get_enrichment_stats(ORG)
    assert stats["total_requests"] == 2
    assert stats["completed"] == 1
    assert stats["pending"] == 1


def test_get_enrichment_stats_top_malicious_types(engine):
    for i in range(3):
        req = engine.create_enrichment_request(ORG, f"evil{i}.com", "domain")
        engine.add_enrichment_result(req["id"], ORG, "src", 90.0, True, [], "", 0.9)
    req_ip = engine.create_enrichment_request(ORG, "1.2.3.4", "ip")
    engine.add_enrichment_result(req_ip["id"], ORG, "src", 80.0, True, [], "", 0.8)
    stats = engine.get_enrichment_stats(ORG)
    types = [t["indicator_type"] for t in stats["top_malicious_types"]]
    assert "domain" in types


# ---------------------------------------------------------------------------
# bulk_enrich
# ---------------------------------------------------------------------------

def test_bulk_enrich_creates_multiple_requests(engine):
    indicators = [
        {"indicator": "1.2.3.4", "indicator_type": "ip"},
        {"indicator": "evil.com", "indicator_type": "domain"},
        {"indicator": "abc123", "indicator_type": "hash"},
    ]
    results = engine.bulk_enrich(ORG, indicators)
    assert len(results) == 3
    assert all(r["status"] == "pending" for r in results)


def test_bulk_enrich_empty_list(engine):
    results = engine.bulk_enrich(ORG, [])
    assert results == []


def test_bulk_enrich_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.bulk_enrich(ORG, [{"indicator": "x", "indicator_type": "bad"}])
