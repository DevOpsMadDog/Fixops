"""Tests for SIEMIntegrationEngine.

Covers: init, register_siem, list_siems, get_siem, update_siem_status,
ingest_event, list_events (filters), correlate_events, create_alert,
list_alerts, resolve_alert, get_siem_stats, org isolation.

Total: 32 tests.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from core.siem_integration_engine import SIEMIntegrationEngine


@pytest.fixture()
def engine(tmp_path):
    return SIEMIntegrationEngine(db_path=str(tmp_path / "test_siem.db"))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "siem_init.db")
    eng = SIEMIntegrationEngine(db_path=db)
    assert eng.db_path == db


def test_init_empty_stats(engine):
    stats = engine.get_siem_stats("org1")
    assert stats["total_siems"] == 0
    assert stats["events_24h"] == 0
    assert stats["alert_count"] == 0


# ---------------------------------------------------------------------------
# 2. SIEM registration
# ---------------------------------------------------------------------------


def test_register_siem_returns_id(engine):
    result = engine.register_siem("org1", {"siem_name": "Splunk Prod", "siem_type": "splunk"})
    assert "siem_id" in result
    assert result["siem_name"] == "Splunk Prod"
    assert result["siem_type"] == "splunk"


def test_register_siem_hashes_token(engine):
    result = engine.register_siem("org1", {"siem_name": "QRadar", "api_token": "secret123"})
    import hashlib
    expected_hash = hashlib.sha256(b"secret123").hexdigest()
    assert result["api_token_hash"] == expected_hash


def test_register_siem_invalid_type_defaults_generic(engine):
    result = engine.register_siem("org1", {"siem_name": "Unknown", "siem_type": "badtype"})
    assert result["siem_type"] == "generic"


def test_register_siem_enabled_flag(engine):
    result = engine.register_siem("org1", {"siem_name": "Elastic", "siem_type": "elastic", "enabled": False})
    assert result["enabled"] is False


def test_register_all_siem_types(engine):
    for siem_type in ("splunk", "qradar", "elastic", "sentinel", "generic"):
        r = engine.register_siem("org1", {"siem_name": siem_type, "siem_type": siem_type})
        assert r["siem_type"] == siem_type


# ---------------------------------------------------------------------------
# 3. List / Get SIEM
# ---------------------------------------------------------------------------


def test_list_siems_empty(engine):
    assert engine.list_siems("org1") == []


def test_list_siems_returns_registered(engine):
    engine.register_siem("org1", {"siem_name": "S1"})
    engine.register_siem("org1", {"siem_name": "S2"})
    siems = engine.list_siems("org1")
    assert len(siems) == 2


def test_get_siem_returns_correct(engine):
    reg = engine.register_siem("org1", {"siem_name": "Sentinel", "siem_type": "sentinel"})
    fetched = engine.get_siem("org1", reg["siem_id"])
    assert fetched is not None
    assert fetched["siem_name"] == "Sentinel"


def test_get_siem_not_found(engine):
    assert engine.get_siem("org1", "nonexistent-id") is None


# ---------------------------------------------------------------------------
# 4. Update status
# ---------------------------------------------------------------------------


def test_update_siem_status_disable(engine):
    reg = engine.register_siem("org1", {"siem_name": "S", "enabled": True})
    ok = engine.update_siem_status("org1", reg["siem_id"], False)
    assert ok is True
    fetched = engine.get_siem("org1", reg["siem_id"])
    assert fetched["enabled"] is False


def test_update_siem_status_not_found(engine):
    ok = engine.update_siem_status("org1", "bad-id", True)
    assert ok is False


# ---------------------------------------------------------------------------
# 5. Event ingestion
# ---------------------------------------------------------------------------


def test_ingest_event_returns_event_id(engine):
    result = engine.ingest_event("org1", {
        "siem_id": "s1",
        "event_type": "auth",
        "severity": "high",
        "source_ip": "10.0.0.1",
        "user": "alice",
        "raw_event": {"action": "login", "outcome": "failure"},
    })
    assert "event_id" in result
    assert result["event_type"] == "auth"
    assert result["severity"] == "high"


def test_ingest_event_normalizes_auth_fields(engine):
    result = engine.ingest_event("org1", {
        "event_type": "auth",
        "severity": "critical",
        "raw_event": {"action": "login", "outcome": "failure", "auth_method": "password"},
    })
    nf = result["normalized_fields"]
    assert nf["action"] == "login"
    assert nf["outcome"] == "failure"
    assert nf["auth_method"] == "password"


def test_ingest_event_normalizes_network_fields(engine):
    result = engine.ingest_event("org1", {
        "event_type": "network",
        "severity": "medium",
        "raw_event": {"protocol": "TCP", "bytes_sent": 1024, "direction": "outbound"},
    })
    nf = result["normalized_fields"]
    assert nf["protocol"] == "TCP"
    assert nf["bytes_sent"] == 1024


def test_ingest_event_invalid_type_defaults(engine):
    result = engine.ingest_event("org1", {"event_type": "badtype", "severity": "info"})
    assert result["event_type"] == "application"


def test_ingest_event_invalid_severity_defaults(engine):
    result = engine.ingest_event("org1", {"severity": "urgent"})
    assert result["severity"] == "info"


# ---------------------------------------------------------------------------
# 6. List events with filters
# ---------------------------------------------------------------------------


def test_list_events_empty(engine):
    assert engine.list_events("org1") == []


def test_list_events_returns_ingested(engine):
    engine.ingest_event("org1", {"event_type": "auth", "severity": "high", "user": "bob"})
    engine.ingest_event("org1", {"event_type": "network", "severity": "low"})
    events = engine.list_events("org1")
    assert len(events) == 2


def test_list_events_filter_by_event_type(engine):
    engine.ingest_event("org1", {"event_type": "auth"})
    engine.ingest_event("org1", {"event_type": "network"})
    auth_events = engine.list_events("org1", event_type="auth")
    assert all(e["event_type"] == "auth" for e in auth_events)
    assert len(auth_events) == 1


def test_list_events_filter_by_severity(engine):
    engine.ingest_event("org1", {"severity": "critical"})
    engine.ingest_event("org1", {"severity": "low"})
    crit = engine.list_events("org1", severity="critical")
    assert len(crit) == 1
    assert crit[0]["severity"] == "critical"


def test_list_events_filter_by_siem_id(engine):
    engine.ingest_event("org1", {"siem_id": "s1"})
    engine.ingest_event("org1", {"siem_id": "s2"})
    s1_events = engine.list_events("org1", siem_id="s1")
    assert len(s1_events) == 1


# ---------------------------------------------------------------------------
# 7. Correlation
# ---------------------------------------------------------------------------


def test_correlate_events_returns_list(engine):
    matched = engine.correlate_events("org1", {"field": "user", "threshold": 3})
    assert isinstance(matched, list)


def test_correlate_events_detects_threshold(engine):
    for _ in range(6):
        engine.ingest_event("org1", {
            "event_type": "auth",
            "severity": "high",
            "user": "attacker",
        })
    matched = engine.correlate_events("org1", {
        "event_type": "auth",
        "field": "user",
        "threshold": 5,
        "window_hours": 1,
        "action": "brute_force",
    })
    assert len(matched) >= 1
    assert matched[0]["group_key"] == "attacker"
    assert matched[0]["event_count"] >= 5
    assert matched[0]["action"] == "brute_force"


def test_correlate_events_below_threshold_no_match(engine):
    for _ in range(3):
        engine.ingest_event("org1", {"event_type": "auth", "user": "normal_user"})
    matched = engine.correlate_events("org1", {"field": "user", "threshold": 10})
    assert len(matched) == 0


# ---------------------------------------------------------------------------
# 8. Alert management
# ---------------------------------------------------------------------------


def test_create_alert_returns_id(engine):
    result = engine.create_alert("org1", {
        "title": "Brute Force Detected",
        "description": "Multiple failed logins",
        "severity": "high",
        "source_event_ids": ["e1", "e2"],
    })
    assert "alert_id" in result
    assert result["status"] == "open"
    assert result["source_event_ids"] == ["e1", "e2"]


def test_create_alert_invalid_severity_defaults(engine):
    result = engine.create_alert("org1", {"title": "Test", "severity": "extreme"})
    assert result["severity"] == "medium"


def test_list_alerts_empty(engine):
    assert engine.list_alerts("org1") == []


def test_list_alerts_filter_by_status(engine):
    engine.create_alert("org1", {"title": "A1", "severity": "high"})
    engine.create_alert("org1", {"title": "A2", "severity": "low"})
    open_alerts = engine.list_alerts("org1", status="open")
    assert len(open_alerts) == 2


def test_resolve_alert(engine):
    alert = engine.create_alert("org1", {"title": "Test Alert", "severity": "medium"})
    ok = engine.resolve_alert("org1", alert["alert_id"], "analyst1", "False positive")
    assert ok is True
    resolved = engine.list_alerts("org1", status="resolved")
    assert len(resolved) == 1
    assert resolved[0]["resolved_by"] == "analyst1"


def test_resolve_alert_not_found(engine):
    ok = engine.resolve_alert("org1", "nonexistent", "analyst1")
    assert ok is False


# ---------------------------------------------------------------------------
# 9. Stats
# ---------------------------------------------------------------------------


def test_stats_structure(engine):
    stats = engine.get_siem_stats("org1")
    assert "total_siems" in stats
    assert "active_siems" in stats
    assert "events_24h" in stats
    assert "events_7d" in stats
    assert "by_siem_type" in stats
    assert "by_severity" in stats
    assert "alert_count" in stats
    assert "open_alerts" in stats


def test_stats_counts_correctly(engine):
    engine.register_siem("org1", {"siem_name": "S1", "enabled": True})
    engine.register_siem("org1", {"siem_name": "S2", "enabled": False})
    engine.ingest_event("org1", {"severity": "high"})
    engine.ingest_event("org1", {"severity": "critical"})
    engine.create_alert("org1", {"title": "Alert1"})

    stats = engine.get_siem_stats("org1")
    assert stats["total_siems"] == 2
    assert stats["active_siems"] == 1
    assert stats["events_24h"] == 2
    assert stats["alert_count"] == 1
    assert stats["open_alerts"] == 1


# ---------------------------------------------------------------------------
# 10. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_siems(engine):
    engine.register_siem("org1", {"siem_name": "Org1 SIEM"})
    engine.register_siem("org2", {"siem_name": "Org2 SIEM"})
    assert len(engine.list_siems("org1")) == 1
    assert len(engine.list_siems("org2")) == 1


def test_org_isolation_events(engine):
    engine.ingest_event("org1", {"user": "alice"})
    engine.ingest_event("org2", {"user": "bob"})
    org1_events = engine.list_events("org1")
    org2_events = engine.list_events("org2")
    assert len(org1_events) == 1
    assert len(org2_events) == 1
    assert org1_events[0]["user"] == "alice"


def test_org_isolation_alerts(engine):
    engine.create_alert("org1", {"title": "Org1 Alert"})
    assert len(engine.list_alerts("org2")) == 0


def test_org_isolation_stats(engine):
    engine.register_siem("org1", {"siem_name": "S"})
    stats_org2 = engine.get_siem_stats("org2")
    assert stats_org2["total_siems"] == 0
