"""Tests for ThreatIndicatorEngine — 35+ tests."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from core.threat_indicator_engine import ThreatIndicatorEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "ti_test.db")
    return ThreatIndicatorEngine(db_path=db)


ORG = "org-ti-1"
ORG2 = "org-ti-2"


def _future_iso(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past_iso(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# Indicator lifecycle
# ---------------------------------------------------------------------------

def test_add_indicator_basic(engine):
    ind = engine.add_indicator(ORG, "192.168.1.1", "ip")
    assert ind["indicator_value"] == "192.168.1.1"
    assert ind["indicator_type"] == "ip"
    assert ind["org_id"] == ORG
    assert ind["active"] == 1
    assert ind["false_positive"] == 0
    assert ind["sighting_count"] == 0


def test_add_indicator_all_fields(engine):
    ind = engine.add_indicator(
        ORG,
        "evil.com",
        "domain",
        source="VirusTotal",
        confidence=0.9,
        severity="high",
        tlp="red",
        tags=["apt28", "ransomware"],
        expiry_at=_future_iso(30),
    )
    assert ind["confidence"] == pytest.approx(0.9)
    assert ind["severity"] == "high"
    assert ind["tlp"] == "red"
    tags = json.loads(ind["tags"])
    assert "apt28" in tags


def test_add_indicator_confidence_clamp_above(engine):
    ind = engine.add_indicator(ORG, "1.2.3.4", "ip", confidence=1.5)
    assert ind["confidence"] == pytest.approx(1.0)


def test_add_indicator_confidence_clamp_below(engine):
    ind = engine.add_indicator(ORG, "1.2.3.4", "ip", confidence=-0.5)
    assert ind["confidence"] == pytest.approx(0.0)


def test_add_indicator_confidence_boundary(engine):
    ind = engine.add_indicator(ORG, "1.2.3.4", "ip", confidence=0.0)
    assert ind["confidence"] == pytest.approx(0.0)
    ind2 = engine.add_indicator(ORG, "1.2.3.5", "ip", confidence=1.0)
    assert ind2["confidence"] == pytest.approx(1.0)


def test_add_indicator_invalid_type(engine):
    with pytest.raises(ValueError, match="indicator_type"):
        engine.add_indicator(ORG, "test", "virus")


def test_add_indicator_invalid_tlp(engine):
    with pytest.raises(ValueError, match="tlp"):
        engine.add_indicator(ORG, "test", "ip", tlp="black")


def test_add_indicator_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.add_indicator(ORG, "test", "ip", severity="unknown")


def test_get_indicator_not_found(engine):
    assert engine.get_indicator("nonexistent", ORG) is None


def test_get_indicator_with_details(engine):
    ind = engine.add_indicator(ORG, "192.0.2.1", "ip")
    engine.enrich_indicator(ind["id"], ORG, "VirusTotal", {"score": 85})
    engine.record_sighting(ind["id"], ORG, "SIEM", "alert fired")
    result = engine.get_indicator(ind["id"], ORG)
    assert result is not None
    assert len(result["enrichments"]) == 1
    assert len(result["sightings"]) == 1


# ---------------------------------------------------------------------------
# Sighting counter
# ---------------------------------------------------------------------------

def test_record_sighting_increments_count(engine):
    ind = engine.add_indicator(ORG, "10.0.0.1", "ip")
    engine.record_sighting(ind["id"], ORG, "EDR", "process injection")
    engine.record_sighting(ind["id"], ORG, "SIEM", "lateral movement")
    updated = engine.get_indicator(ind["id"], ORG)
    assert updated["sighting_count"] == 2


def test_record_sighting_updates_last_seen(engine):
    ind = engine.add_indicator(ORG, "10.0.0.2", "ip")
    original_last_seen = ind["last_seen"]
    engine.record_sighting(ind["id"], ORG)
    updated = engine.get_indicator(ind["id"], ORG)
    assert updated["last_seen"] >= original_last_seen


def test_record_sighting_invalid_severity(engine):
    ind = engine.add_indicator(ORG, "10.0.0.3", "ip")
    with pytest.raises(ValueError, match="severity"):
        engine.record_sighting(ind["id"], ORG, severity="extreme")


def test_record_sighting_stored(engine):
    ind = engine.add_indicator(ORG, "10.0.0.4", "ip")
    engine.record_sighting(ind["id"], ORG, "WAF", "blocked request", "high")
    result = engine.get_indicator(ind["id"], ORG)
    sighting = result["sightings"][0]
    assert sighting["source_system"] == "WAF"
    assert sighting["context"] == "blocked request"
    assert sighting["severity"] == "high"


# ---------------------------------------------------------------------------
# False positive and expiry
# ---------------------------------------------------------------------------

def test_mark_false_positive(engine):
    ind = engine.add_indicator(ORG, "safe.com", "domain")
    result = engine.mark_false_positive(ind["id"], ORG)
    assert result["false_positive"] == 1
    assert result["active"] == 0


def test_mark_false_positive_not_found(engine):
    result = engine.mark_false_positive("nonexistent", ORG)
    assert result is None


def test_expire_indicator(engine):
    ind = engine.add_indicator(ORG, "old.com", "domain")
    result = engine.expire_indicator(ind["id"], ORG)
    assert result["active"] == 0


def test_expire_indicator_not_found(engine):
    result = engine.expire_indicator("nonexistent", ORG)
    assert result is None


# ---------------------------------------------------------------------------
# Active and expired queries
# ---------------------------------------------------------------------------

def test_get_active_indicators(engine):
    engine.add_indicator(ORG, "active1.com", "domain")
    engine.add_indicator(ORG, "active2.com", "domain")
    results = engine.get_active_indicators(ORG)
    assert len(results) == 2


def test_get_active_indicators_excludes_expired(engine):
    ind = engine.add_indicator(ORG, "old.com", "domain", expiry_at=_past_iso(1))
    results = engine.get_active_indicators(ORG)
    ids = [r["id"] for r in results]
    assert ind["id"] not in ids


def test_get_active_indicators_includes_future_expiry(engine):
    ind = engine.add_indicator(ORG, "future.com", "domain", expiry_at=_future_iso(30))
    results = engine.get_active_indicators(ORG)
    ids = [r["id"] for r in results]
    assert ind["id"] in ids


def test_get_active_indicators_filter_type(engine):
    engine.add_indicator(ORG, "1.2.3.4", "ip")
    engine.add_indicator(ORG, "evil.com", "domain")
    results = engine.get_active_indicators(ORG, indicator_type="ip")
    assert all(r["indicator_type"] == "ip" for r in results)
    assert len(results) == 1


def test_get_active_indicators_filter_severity(engine):
    engine.add_indicator(ORG, "1.2.3.4", "ip", severity="critical")
    engine.add_indicator(ORG, "2.3.4.5", "ip", severity="low")
    results = engine.get_active_indicators(ORG, severity="critical")
    assert len(results) == 1
    assert results[0]["severity"] == "critical"


def test_get_expired_indicators(engine):
    ind = engine.add_indicator(ORG, "expired.com", "domain", expiry_at=_past_iso(1))
    results = engine.get_expired_indicators(ORG)
    ids = [r["id"] for r in results]
    assert ind["id"] in ids


def test_get_expired_excludes_active_future(engine):
    engine.add_indicator(ORG, "fresh.com", "domain", expiry_at=_future_iso(10))
    results = engine.get_expired_indicators(ORG)
    assert len(results) == 0


def test_get_expired_excludes_manually_expired(engine):
    # Manually expired (active=0) should NOT appear in get_expired (they're already inactive)
    # get_expired looks for active=1 AND past expiry_at
    ind = engine.add_indicator(ORG, "manual.com", "domain", expiry_at=_past_iso(1))
    engine.expire_indicator(ind["id"], ORG)  # now active=0
    results = engine.get_expired_indicators(ORG)
    ids = [r["id"] for r in results]
    assert ind["id"] not in ids


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def test_enrich_indicator(engine):
    ind = engine.add_indicator(ORG, "malware.com", "domain")
    enr = engine.enrich_indicator(ind["id"], ORG, "VirusTotal", {"positives": 55, "total": 70})
    assert enr["enrichment_source"] == "VirusTotal"
    data = json.loads(enr["enrichment_data"])
    assert data["positives"] == 55


def test_enrich_updates_last_seen(engine):
    ind = engine.add_indicator(ORG, "malware2.com", "domain")
    original = ind["last_seen"]
    engine.enrich_indicator(ind["id"], ORG, "AbuseIPDB", {})
    updated = engine.get_indicator(ind["id"], ORG)
    assert updated["last_seen"] >= original


def test_multiple_enrichments(engine):
    ind = engine.add_indicator(ORG, "multi.com", "domain")
    engine.enrich_indicator(ind["id"], ORG, "Source1", {"key": "val1"})
    engine.enrich_indicator(ind["id"], ORG, "Source2", {"key": "val2"})
    result = engine.get_indicator(ind["id"], ORG)
    assert len(result["enrichments"]) == 2


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def test_search_indicators_found(engine):
    engine.add_indicator(ORG, "192.168.100.1", "ip")
    engine.add_indicator(ORG, "192.168.100.2", "ip")
    engine.add_indicator(ORG, "10.0.0.1", "ip")
    results = engine.search_indicators(ORG, "192.168")
    assert len(results) == 2


def test_search_indicators_not_found(engine):
    engine.add_indicator(ORG, "benign.com", "domain")
    results = engine.search_indicators(ORG, "evil")
    assert len(results) == 0


def test_search_indicators_exact_match(engine):
    engine.add_indicator(ORG, "exactmatch.com", "domain")
    results = engine.search_indicators(ORG, "exactmatch.com")
    assert len(results) == 1


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def test_get_summary_empty(engine):
    s = engine.get_summary(ORG)
    assert s["total"] == 0
    assert s["active_count"] == 0
    assert s["false_positive_count"] == 0
    assert s["high_confidence_count"] == 0
    assert s["expiring_soon"] == 0


def test_get_summary_counts(engine):
    engine.add_indicator(ORG, "1.2.3.4", "ip", confidence=0.9, severity="high")
    engine.add_indicator(ORG, "evil.com", "domain", confidence=0.3, severity="medium")
    ind3 = engine.add_indicator(ORG, "bad.ru", "domain")
    engine.mark_false_positive(ind3["id"], ORG)

    s = engine.get_summary(ORG)
    assert s["total"] == 3
    assert s["active_count"] == 2
    assert s["false_positive_count"] == 1
    assert s["high_confidence_count"] == 1
    assert s["by_type"].get("ip") == 1
    assert s["by_type"].get("domain") == 2
    assert s["by_severity"].get("high") == 1


def test_get_summary_expiring_soon(engine):
    engine.add_indicator(ORG, "soon.com", "domain", expiry_at=_future_iso(3))
    engine.add_indicator(ORG, "later.com", "domain", expiry_at=_future_iso(30))
    s = engine.get_summary(ORG)
    assert s["expiring_soon"] == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_active(engine):
    engine.add_indicator(ORG, "org1.com", "domain")
    engine.add_indicator(ORG2, "org2.com", "domain")
    assert len(engine.get_active_indicators(ORG)) == 1
    assert len(engine.get_active_indicators(ORG2)) == 1


def test_org_isolation_get(engine):
    ind = engine.add_indicator(ORG, "secret.com", "domain")
    assert engine.get_indicator(ind["id"], ORG2) is None


def test_org_isolation_search(engine):
    engine.add_indicator(ORG, "shared.com", "domain")
    results = engine.search_indicators(ORG2, "shared")
    assert len(results) == 0


def test_org_isolation_summary(engine):
    engine.add_indicator(ORG, "test.com", "domain")
    s = engine.get_summary(ORG2)
    assert s["total"] == 0


def test_org_isolation_false_positive(engine):
    ind = engine.add_indicator(ORG, "fp.com", "domain")
    result = engine.mark_false_positive(ind["id"], ORG2)
    # Should return None because org_id doesn't match
    assert result is None or result.get("false_positive") == 0
