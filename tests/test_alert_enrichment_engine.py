"""Tests for AlertEnrichmentEngine.

Covers: dedup on alert_id, severity_multiplier in risk_score,
confidence_score max(existing, new), source success/error_count increment,
api_key SHA-256 hashing, high_risk filter, enrichment_queue priority
ordering, org isolation, context updates, toggle source.

Total: 40 tests.
"""

from __future__ import annotations

import hashlib
import os
import pytest

from core.alert_enrichment_engine import AlertEnrichmentEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    return AlertEnrichmentEngine(db_path=str(tmp_path / "ae_test.db"))


@pytest.fixture()
def alert(engine):
    return engine.submit_alert(
        org_id="org1",
        alert_id="ALERT-001",
        alert_source="siem",
        severity="high",
        raw_indicator="192.168.1.1",
        indicator_type="ip",
    )


@pytest.fixture()
def source(engine):
    return engine.register_source(
        org_id="org1",
        source_name="VirusTotal",
        source_type="threat_intel",
        priority=1,
        api_key="secret123",
    )


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ae_init.db")
    AlertEnrichmentEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ae_idem.db")
    AlertEnrichmentEngine(db_path=db)
    AlertEnrichmentEngine(db_path=db)


# ===========================================================================
# 2. submit_alert — basic and dedup
# ===========================================================================

def test_submit_alert_returns_record(alert):
    assert alert["alert_id"] == "ALERT-001"
    assert alert["enrichment_status"] == "pending"
    assert alert["org_id"] == "org1"


def test_submit_alert_dedup_returns_existing(engine, alert):
    dup = engine.submit_alert(
        org_id="org1",
        alert_id="ALERT-001",
        alert_source="edr",
        severity="critical",
        raw_indicator="10.0.0.1",
        indicator_type="ip",
    )
    assert dup["id"] == alert["id"]
    assert dup["alert_source"] == "siem"  # original unchanged


def test_submit_alert_different_org_allowed(engine, alert):
    other = engine.submit_alert(
        org_id="org2",
        alert_id="ALERT-001",
        alert_source="siem",
        severity="low",
        raw_indicator="1.1.1.1",
        indicator_type="ip",
    )
    assert other["org_id"] == "org2"
    assert other["id"] != alert["id"]


def test_submit_alert_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.submit_alert("org1", "A-BAD", "siem", "unknown", "1.1.1.1", "ip")


def test_submit_alert_invalid_indicator_type(engine):
    with pytest.raises(ValueError, match="indicator_type"):
        engine.submit_alert("org1", "A-BAD2", "siem", "high", "1.1.1.1", "widget")


def test_submit_alert_initial_risk_zero(alert):
    assert alert["risk_score"] == 0.0
    assert alert["confidence_score"] == 0.0
    assert alert["ioc_matches"] == 0


# ===========================================================================
# 3. enrich_alert — risk_score, confidence, ioc accumulation
# ===========================================================================

def test_enrich_alert_sets_status_enriched(engine, alert):
    result = engine.enrich_alert(
        alert_id="ALERT-001",
        org_id="org1",
        source_name="VT",
        result_type="ioc_match",
        result_data="matched",
        ioc_matches=2,
        confidence_score=0.8,
    )
    assert result["enrichment_status"] == "enriched"


def test_enrich_alert_risk_score_high_severity(engine):
    """high severity → multiplier 0.75 → risk = 0.8 * 0.75 * 10 = 6.0"""
    engine.submit_alert("org1", "A-HIGH", "siem", "high", "x.com", "domain")
    result = engine.enrich_alert(
        "A-HIGH", "org1", "src", "ioc_match", "", confidence_score=0.8
    )
    assert abs(result["risk_score"] - 6.0) < 0.001


def test_enrich_alert_risk_score_critical_severity(engine):
    """critical → multiplier 1.0 → risk = 1.0 * 1.0 * 10 = 10.0"""
    engine.submit_alert("org1", "A-CRIT", "siem", "critical", "evil.exe", "hash")
    result = engine.enrich_alert(
        "A-CRIT", "org1", "src", "ioc_match", "", confidence_score=1.0
    )
    assert abs(result["risk_score"] - 10.0) < 0.001


def test_enrich_alert_risk_score_medium_severity(engine):
    """medium → multiplier 0.5 → risk = 0.6 * 0.5 * 10 = 3.0"""
    engine.submit_alert("org1", "A-MED", "siem", "medium", "user@x.com", "email")
    result = engine.enrich_alert(
        "A-MED", "org1", "src", "reputation", "", confidence_score=0.6
    )
    assert abs(result["risk_score"] - 3.0) < 0.001


def test_enrich_alert_risk_score_low_severity(engine):
    """low → multiplier 0.25 → risk = 1.0 * 0.25 * 10 = 2.5"""
    engine.submit_alert("org1", "A-LOW", "siem", "low", "HKCU\\run", "registry")
    result = engine.enrich_alert(
        "A-LOW", "org1", "src", "ioc_match", "", confidence_score=1.0
    )
    assert abs(result["risk_score"] - 2.5) < 0.001


def test_enrich_alert_confidence_takes_max(engine, alert):
    """confidence_score = max(existing, new)"""
    engine.enrich_alert("ALERT-001", "org1", "s1", "ioc_match", "", confidence_score=0.6)
    result = engine.enrich_alert("ALERT-001", "org1", "s2", "reputation", "", confidence_score=0.4)
    # max(0.6, 0.4) = 0.6
    assert result["confidence_score"] == pytest.approx(0.6)


def test_enrich_alert_confidence_improves(engine, alert):
    engine.enrich_alert("ALERT-001", "org1", "s1", "ioc_match", "", confidence_score=0.5)
    result = engine.enrich_alert("ALERT-001", "org1", "s2", "ioc_match", "", confidence_score=0.9)
    assert result["confidence_score"] == pytest.approx(0.9)


def test_enrich_alert_ioc_matches_accumulate(engine, alert):
    engine.enrich_alert("ALERT-001", "org1", "s1", "ioc_match", "", ioc_matches=3)
    result = engine.enrich_alert("ALERT-001", "org1", "s2", "ioc_match", "", ioc_matches=5)
    assert result["ioc_matches"] == 8


def test_enrich_alert_invalid_result_type(engine, alert):
    with pytest.raises(ValueError, match="result_type"):
        engine.enrich_alert("ALERT-001", "org1", "s1", "bogus", "")


def test_enrich_alert_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.enrich_alert("MISSING", "org1", "s1", "ioc_match", "")


def test_enrich_alert_increments_source_success(engine, alert, source):
    engine.enrich_alert("ALERT-001", "org1", "VirusTotal", "ioc_match", "hit")
    engine.enrich_alert("ALERT-001", "org1", "VirusTotal", "ioc_match", "hit2")
    summary = engine.get_enrichment_summary("org1")
    top = {s["source_name"]: s for s in summary["top_sources"]}
    assert top["VirusTotal"]["success_count"] == 2


# ===========================================================================
# 4. mark_failed
# ===========================================================================

def test_mark_failed_sets_status(engine, alert, source):
    result = engine.mark_failed("ALERT-001", "org1", "VirusTotal", "timeout")
    assert result["enrichment_status"] == "failed"


def test_mark_failed_increments_error_count(engine, alert, source):
    engine.mark_failed("ALERT-001", "org1", "VirusTotal", "err1")
    engine.mark_failed("ALERT-001", "org1", "VirusTotal", "err2")
    summary = engine.get_enrichment_summary("org1")
    top = {s["source_name"]: s for s in summary["top_sources"]}
    assert top["VirusTotal"]["error_count"] == 2


def test_mark_failed_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.mark_failed("GHOST", "org1", "src", "err")


# ===========================================================================
# 5. add_context
# ===========================================================================

def test_add_context_sets_both(engine, alert):
    result = engine.add_context("ALERT-001", "org1", threat_context="APT29", asset_context="web01")
    assert result["threat_context"] == "APT29"
    assert result["asset_context"] == "web01"


def test_add_context_empty_string_not_overwrite(engine, alert):
    engine.add_context("ALERT-001", "org1", threat_context="APT28")
    result = engine.add_context("ALERT-001", "org1", threat_context="", asset_context="db02")
    # empty threat_context → existing preserved
    assert result["threat_context"] == "APT28"
    assert result["asset_context"] == "db02"


def test_add_context_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.add_context("GHOST", "org1")


# ===========================================================================
# 6. register_source — SHA-256 api_key
# ===========================================================================

def test_register_source_hashes_api_key(engine):
    src = engine.register_source("org1", "OTX", "threat_intel", 2, api_key="my-secret")
    expected_hash = hashlib.sha256(b"my-secret").hexdigest()
    assert src["api_key_hash"] == expected_hash


def test_register_source_empty_key_blank_hash(engine):
    src = engine.register_source("org1", "NoKey", "reputation", 3, api_key="")
    assert src["api_key_hash"] == ""


def test_register_source_invalid_type(engine):
    with pytest.raises(ValueError, match="source_type"):
        engine.register_source("org1", "Bad", "unknown_type", 1)


def test_register_source_enabled_by_default(source):
    assert source["enabled"] == 1


# ===========================================================================
# 7. toggle_source
# ===========================================================================

def test_toggle_source_disable(engine, source):
    result = engine.toggle_source(source["id"], "org1", enabled=False)
    assert result["enabled"] == 0


def test_toggle_source_re_enable(engine, source):
    engine.toggle_source(source["id"], "org1", enabled=False)
    result = engine.toggle_source(source["id"], "org1", enabled=True)
    assert result["enabled"] == 1


def test_toggle_source_wrong_org_raises(engine, source):
    with pytest.raises(KeyError):
        engine.toggle_source(source["id"], "org_evil", enabled=False)


# ===========================================================================
# 8. get_enrichment_queue — priority ordering
# ===========================================================================

def test_queue_critical_first(engine):
    engine.submit_alert("org1", "A-LOW2", "siem", "low", "x", "ip")
    engine.submit_alert("org1", "A-CRIT2", "siem", "critical", "y", "ip")
    engine.submit_alert("org1", "A-MED2", "siem", "medium", "z", "ip")
    queue = engine.get_enrichment_queue("org1")
    severities = [q["severity"] for q in queue]
    assert severities[0] == "critical"
    assert severities[-1] == "low"


def test_queue_excludes_enriched(engine, alert):
    engine.enrich_alert("ALERT-001", "org1", "s1", "ioc_match", "")
    queue = engine.get_enrichment_queue("org1")
    ids = [q["alert_id"] for q in queue]
    assert "ALERT-001" not in ids


# ===========================================================================
# 9. get_enrichment_summary
# ===========================================================================

def test_summary_counts_by_status(engine):
    engine.submit_alert("org1", "B1", "siem", "high", "1.1.1.1", "ip")
    engine.submit_alert("org1", "B2", "siem", "low", "2.2.2.2", "ip")
    engine.enrich_alert("B1", "org1", "s", "ioc_match", "")
    summary = engine.get_enrichment_summary("org1")
    assert summary["total"] == 2
    assert summary["by_status"].get("enriched") == 1
    assert summary["by_status"].get("pending") == 1


def test_summary_avg_confidence(engine):
    engine.submit_alert("org1", "C1", "siem", "high", "a", "ip")
    engine.submit_alert("org1", "C2", "siem", "high", "b", "ip")
    engine.enrich_alert("C1", "org1", "s", "ioc_match", "", confidence_score=0.8)
    engine.enrich_alert("C2", "org1", "s", "ioc_match", "", confidence_score=0.4)
    summary = engine.get_enrichment_summary("org1")
    assert summary["avg_confidence"] == pytest.approx(0.6, abs=0.01)


# ===========================================================================
# 10. get_high_risk_alerts
# ===========================================================================

def test_high_risk_filter(engine):
    engine.submit_alert("org1", "HR1", "siem", "critical", "evil.com", "domain")
    engine.submit_alert("org1", "HR2", "siem", "low", "ok.com", "domain")
    engine.enrich_alert("HR1", "org1", "s", "ioc_match", "", confidence_score=1.0)
    engine.enrich_alert("HR2", "org1", "s", "reputation", "", confidence_score=0.1)
    high = engine.get_high_risk_alerts("org1", min_risk=7.0)
    alert_ids = [h["alert_id"] for h in high]
    assert "HR1" in alert_ids
    assert "HR2" not in alert_ids


def test_high_risk_ordered_descending(engine):
    engine.submit_alert("org1", "R1", "siem", "critical", "a", "ip")
    engine.submit_alert("org1", "R2", "siem", "critical", "b", "ip")
    engine.enrich_alert("R1", "org1", "s", "ioc_match", "", confidence_score=0.9)
    engine.enrich_alert("R2", "org1", "s", "ioc_match", "", confidence_score=0.8)
    high = engine.get_high_risk_alerts("org1", min_risk=0.0)
    scores = [h["risk_score"] for h in high]
    assert scores == sorted(scores, reverse=True)


# ===========================================================================
# 11. get_alert_detail
# ===========================================================================

def test_alert_detail_includes_history(engine, alert):
    engine.enrich_alert("ALERT-001", "org1", "VT", "ioc_match", "match1")
    detail = engine.get_alert_detail("ALERT-001", "org1")
    assert detail is not None
    assert len(detail["history"]) == 1
    assert detail["history"][0]["source_name"] == "VT"


def test_alert_detail_not_found_returns_none(engine):
    assert engine.get_alert_detail("GHOST", "org1") is None


# ===========================================================================
# 12. Org isolation
# ===========================================================================

def test_org_isolation_submit(engine, alert):
    result = engine.get_alert_detail("ALERT-001", "org2")
    assert result is None


def test_org_isolation_queue(engine):
    engine.submit_alert("org1", "ISO1", "siem", "critical", "x", "ip")
    engine.submit_alert("org2", "ISO2", "siem", "critical", "y", "ip")
    q1 = engine.get_enrichment_queue("org1")
    q2 = engine.get_enrichment_queue("org2")
    ids1 = {q["alert_id"] for q in q1}
    ids2 = {q["alert_id"] for q in q2}
    assert "ISO1" in ids1 and "ISO2" not in ids1
    assert "ISO2" in ids2 and "ISO1" not in ids2
