"""Tests for CyberThreatIntelligenceEngine — ALDECI."""

from __future__ import annotations

import pytest

from core.cyber_threat_intelligence_engine import CyberThreatIntelligenceEngine


@pytest.fixture
def engine(tmp_path):
    return CyberThreatIntelligenceEngine(db_path=str(tmp_path / "cti.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _report(engine, org_id="org1", **kwargs):
    data = dict(
        title="APT29 Campaign",
        intel_type="tactical",
        tlp="amber",
        source_type="osint",
        confidence_score=0.75,
    )
    data.update(kwargs)
    return engine.create_intel_report(org_id, data)


# ---------------------------------------------------------------------------
# create_intel_report — validation
# ---------------------------------------------------------------------------

def test_create_report_missing_title_raises(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_intel_report("org1", {"intel_type": "tactical", "tlp": "amber", "source_type": "osint"})


def test_create_report_empty_title_raises(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_intel_report("org1", {"title": "  ", "intel_type": "tactical", "tlp": "amber", "source_type": "osint"})


def test_create_report_invalid_intel_type_raises(engine):
    with pytest.raises(ValueError, match="intel_type"):
        engine.create_intel_report("org1", {"title": "T", "intel_type": "bad", "tlp": "amber", "source_type": "osint"})


def test_create_report_invalid_tlp_raises(engine):
    with pytest.raises(ValueError, match="tlp"):
        engine.create_intel_report("org1", {"title": "T", "intel_type": "tactical", "tlp": "purple", "source_type": "osint"})


def test_create_report_invalid_source_type_raises(engine):
    with pytest.raises(ValueError, match="source_type"):
        engine.create_intel_report("org1", {"title": "T", "intel_type": "tactical", "tlp": "amber", "source_type": "unknown"})


# ---------------------------------------------------------------------------
# create_intel_report — all valid enum values
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("intel_type", ["strategic", "tactical", "operational", "technical"])
def test_create_report_all_intel_types(engine, intel_type):
    r = _report(engine, intel_type=intel_type)
    assert r["intel_type"] == intel_type
    assert r["status"] == "draft"
    assert r["published_at"] is None
    assert "id" in r
    assert "created_at" in r


@pytest.mark.parametrize("tlp", ["white", "green", "amber", "red"])
def test_create_report_all_tlp_values(engine, tlp):
    r = _report(engine, tlp=tlp)
    assert r["tlp"] == tlp


@pytest.mark.parametrize("source_type", ["osint", "isac", "commercial", "government", "internal", "partner"])
def test_create_report_all_source_types(engine, source_type):
    r = _report(engine, source_type=source_type)
    assert r["source_type"] == source_type


def test_create_report_confidence_score_clamped_high(engine):
    r = _report(engine, confidence_score=1.5)
    assert r["confidence_score"] == 1.0


def test_create_report_confidence_score_clamped_low(engine):
    r = _report(engine, confidence_score=-0.5)
    assert r["confidence_score"] == 0.0


def test_create_report_default_status_draft(engine):
    r = _report(engine)
    assert r["status"] == "draft"
    assert r["org_id"] == "org1"


def test_create_report_with_tags(engine):
    r = _report(engine, tags_json=["apt29", "russia", "espionage"])
    assert "apt29" in r["tags_json"]


# ---------------------------------------------------------------------------
# list_reports and get_report
# ---------------------------------------------------------------------------

def test_list_reports_empty(engine):
    assert engine.list_reports("org1") == []


def test_list_reports_returns_own_org_only(engine):
    _report(engine, org_id="org1")
    _report(engine, org_id="org2")
    results = engine.list_reports("org1")
    assert len(results) == 1
    assert results[0]["org_id"] == "org1"


def test_list_reports_filter_intel_type(engine):
    _report(engine, intel_type="strategic")
    _report(engine, intel_type="tactical")
    results = engine.list_reports("org1", intel_type="strategic")
    assert len(results) == 1
    assert results[0]["intel_type"] == "strategic"


def test_list_reports_filter_tlp(engine):
    _report(engine, tlp="red")
    _report(engine, tlp="green")
    results = engine.list_reports("org1", tlp="red")
    assert len(results) == 1
    assert results[0]["tlp"] == "red"


def test_list_reports_filter_status(engine):
    r = _report(engine)
    engine.publish_report("org1", r["id"])
    results = engine.list_reports("org1", status="published")
    assert len(results) == 1
    assert results[0]["status"] == "published"


def test_get_report_found(engine):
    r = _report(engine)
    fetched = engine.get_report("org1", r["id"])
    assert fetched is not None
    assert fetched["id"] == r["id"]


def test_get_report_not_found(engine):
    assert engine.get_report("org1", "nonexistent") is None


def test_get_report_wrong_org(engine):
    r = _report(engine, org_id="org1")
    assert engine.get_report("org2", r["id"]) is None


# ---------------------------------------------------------------------------
# publish_report
# ---------------------------------------------------------------------------

def test_publish_report_sets_status_and_published_at(engine):
    r = _report(engine)
    published = engine.publish_report("org1", r["id"])
    assert published["status"] == "published"
    assert published["published_at"] is not None


def test_publish_report_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.publish_report("org1", "nonexistent-id")


def test_publish_report_wrong_org_raises(engine):
    r = _report(engine, org_id="org1")
    with pytest.raises(KeyError):
        engine.publish_report("org2", r["id"])


# ---------------------------------------------------------------------------
# add_ioc_to_report and list_iocs
# ---------------------------------------------------------------------------

def test_add_ioc_invalid_type_raises(engine):
    r = _report(engine)
    with pytest.raises(ValueError, match="ioc_type"):
        engine.add_ioc_to_report("org1", r["id"], {"ioc_type": "bitcoin", "value": "1abc"})


def test_add_ioc_missing_value_raises(engine):
    r = _report(engine)
    with pytest.raises(ValueError, match="value"):
        engine.add_ioc_to_report("org1", r["id"], {"ioc_type": "ip", "value": ""})


@pytest.mark.parametrize("ioc_type", ["ip", "domain", "hash", "url", "email", "file_path", "registry_key"])
def test_add_ioc_all_types(engine, ioc_type):
    r = _report(engine)
    ioc = engine.add_ioc_to_report("org1", r["id"], {"ioc_type": ioc_type, "value": "test-value"})
    assert ioc["ioc_type"] == ioc_type
    assert ioc["report_id"] == r["id"]
    assert "id" in ioc
    assert "created_at" in ioc


def test_add_ioc_confidence_defaults(engine):
    r = _report(engine)
    ioc = engine.add_ioc_to_report("org1", r["id"], {"ioc_type": "ip", "value": "1.2.3.4"})
    assert ioc["confidence"] == 0.5


def test_list_iocs_empty(engine):
    assert engine.list_iocs("org1") == []


def test_list_iocs_by_org(engine):
    r1 = _report(engine, org_id="org1")
    r2 = _report(engine, org_id="org2")
    engine.add_ioc_to_report("org1", r1["id"], {"ioc_type": "ip", "value": "1.1.1.1"})
    engine.add_ioc_to_report("org2", r2["id"], {"ioc_type": "ip", "value": "2.2.2.2"})
    assert len(engine.list_iocs("org1")) == 1
    assert len(engine.list_iocs("org2")) == 1


def test_list_iocs_filter_report_id(engine):
    r1 = _report(engine)
    r2 = _report(engine)
    engine.add_ioc_to_report("org1", r1["id"], {"ioc_type": "ip", "value": "1.1.1.1"})
    engine.add_ioc_to_report("org1", r2["id"], {"ioc_type": "domain", "value": "evil.com"})
    results = engine.list_iocs("org1", report_id=r1["id"])
    assert len(results) == 1
    assert results[0]["value"] == "1.1.1.1"


def test_list_iocs_filter_ioc_type(engine):
    r = _report(engine)
    engine.add_ioc_to_report("org1", r["id"], {"ioc_type": "ip", "value": "1.1.1.1"})
    engine.add_ioc_to_report("org1", r["id"], {"ioc_type": "domain", "value": "evil.com"})
    results = engine.list_iocs("org1", ioc_type="ip")
    assert len(results) == 1
    assert results[0]["ioc_type"] == "ip"


# ---------------------------------------------------------------------------
# get_intel_stats
# ---------------------------------------------------------------------------

def test_get_intel_stats_empty(engine):
    stats = engine.get_intel_stats("org1")
    assert stats["total_reports"] == 0
    assert stats["published_reports"] == 0
    assert stats["total_iocs"] == 0
    assert stats["high_confidence_reports"] == 0
    assert stats["by_intel_type"] == {}
    assert stats["by_tlp"] == {}
    assert stats["by_source_type"] == {}


def test_get_intel_stats_counts(engine):
    r1 = _report(engine, intel_type="tactical", tlp="amber", source_type="osint", confidence_score=0.9)
    r2 = _report(engine, intel_type="strategic", tlp="red", source_type="government", confidence_score=0.5)
    engine.publish_report("org1", r1["id"])
    engine.add_ioc_to_report("org1", r1["id"], {"ioc_type": "ip", "value": "1.2.3.4"})
    engine.add_ioc_to_report("org1", r1["id"], {"ioc_type": "domain", "value": "evil.com"})

    stats = engine.get_intel_stats("org1")
    assert stats["total_reports"] == 2
    assert stats["published_reports"] == 1
    assert stats["total_iocs"] == 2
    assert stats["high_confidence_reports"] == 1
    assert stats["by_intel_type"]["tactical"] == 1
    assert stats["by_intel_type"]["strategic"] == 1
    assert stats["by_tlp"]["amber"] == 1
    assert stats["by_tlp"]["red"] == 1
    assert stats["by_source_type"]["osint"] == 1
    assert stats["by_source_type"]["government"] == 1


def test_get_intel_stats_org_isolation(engine):
    _report(engine, org_id="org1")
    _report(engine, org_id="org2")
    stats1 = engine.get_intel_stats("org1")
    stats2 = engine.get_intel_stats("org2")
    assert stats1["total_reports"] == 1
    assert stats2["total_reports"] == 1
