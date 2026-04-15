"""Tests for SecurityEventCorrelationEngine — 30+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def engine(tmp_path):
    from core.security_event_correlation_engine import SecurityEventCorrelationEngine
    return SecurityEventCorrelationEngine(db_path=str(tmp_path / "sec_corr.db"))


ORG = "test-org-corr"
ORG2 = "other-org-corr"


# ---------------------------------------------------------------------------
# Event ingestion
# ---------------------------------------------------------------------------

def test_ingest_event_basic(engine):
    evt = engine.ingest_event(ORG, {"source_system": "EDR", "event_type": "process_create", "severity": "medium"})
    assert evt["id"]
    assert evt["source_system"] == "EDR"
    assert evt["event_type"] == "process_create"
    assert evt["severity"] == "medium"
    assert evt["org_id"] == ORG


def test_ingest_event_all_fields(engine):
    evt = engine.ingest_event(ORG, {
        "source_system": "SIEM",
        "event_type": "login_failure",
        "severity": "high",
        "entity_id": "user-42",
        "entity_type": "user",
        "raw_data": {"ip": "1.2.3.4", "attempts": 5},
        "timestamp": "2026-01-01T00:00:00+00:00",
    })
    assert evt["entity_id"] == "user-42"
    assert evt["entity_type"] == "user"
    assert isinstance(evt["raw_data"], dict)
    assert evt["raw_data"]["ip"] == "1.2.3.4"
    assert evt["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_ingest_event_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.ingest_event(ORG, {"severity": "extreme"})


def test_ingest_event_default_severity(engine):
    evt = engine.ingest_event(ORG, {"source_system": "WAF", "event_type": "sqli_attempt"})
    assert evt["severity"] == "medium"


def test_ingest_event_all_severities(engine):
    for sev in ("critical", "high", "medium", "low", "info"):
        evt = engine.ingest_event(ORG, {"event_type": "test", "severity": sev})
        assert evt["severity"] == sev


# ---------------------------------------------------------------------------
# List events
# ---------------------------------------------------------------------------

def test_list_events_empty(engine):
    assert engine.list_events(ORG) == []


def test_list_events_returns_ingested(engine):
    engine.ingest_event(ORG, {"source_system": "NDR", "event_type": "port_scan", "severity": "low"})
    events = engine.list_events(ORG)
    assert len(events) == 1
    assert events[0]["source_system"] == "NDR"


def test_list_events_filter_source_system(engine):
    engine.ingest_event(ORG, {"source_system": "EDR", "event_type": "malware", "severity": "high"})
    engine.ingest_event(ORG, {"source_system": "SIEM", "event_type": "login_failure", "severity": "medium"})
    result = engine.list_events(ORG, source_system="EDR")
    assert len(result) == 1
    assert result[0]["source_system"] == "EDR"


def test_list_events_filter_event_type(engine):
    engine.ingest_event(ORG, {"event_type": "malware_detected", "severity": "critical"})
    engine.ingest_event(ORG, {"event_type": "login_failure", "severity": "medium"})
    result = engine.list_events(ORG, event_type="malware_detected")
    assert len(result) == 1
    assert result[0]["event_type"] == "malware_detected"


def test_list_events_filter_severity(engine):
    engine.ingest_event(ORG, {"event_type": "a", "severity": "critical"})
    engine.ingest_event(ORG, {"event_type": "b", "severity": "low"})
    result = engine.list_events(ORG, severity="critical")
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_list_events_org_isolation(engine):
    engine.ingest_event(ORG, {"event_type": "test", "severity": "low"})
    assert engine.list_events(ORG2) == []


def test_list_events_limit(engine):
    for i in range(5):
        engine.ingest_event(ORG, {"event_type": f"type_{i}", "severity": "low"})
    result = engine.list_events(ORG, limit=3)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------

def test_create_rule_basic(engine):
    rule = engine.create_correlation_rule(ORG, {
        "name": "Brute Force Detection",
        "pattern": ["login_failure"],
        "time_window_seconds": 60,
        "min_count": 5,
        "output_severity": "high",
    })
    assert rule["id"]
    assert rule["name"] == "Brute Force Detection"
    assert rule["pattern"] == ["login_failure"]
    assert rule["time_window_seconds"] == 60
    assert rule["min_count"] == 5
    assert rule["output_severity"] == "high"
    assert rule["enabled"] is True


def test_create_rule_missing_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_correlation_rule(ORG, {"pattern": ["login_failure"]})


def test_create_rule_invalid_severity(engine):
    with pytest.raises(ValueError, match="output_severity"):
        engine.create_correlation_rule(ORG, {"name": "X", "output_severity": "fatal"})


def test_list_rules_empty(engine):
    assert engine.list_correlation_rules(ORG) == []


def test_list_rules_returns_created(engine):
    engine.create_correlation_rule(ORG, {"name": "Rule A", "pattern": ["port_scan"]})
    rules = engine.list_correlation_rules(ORG)
    assert len(rules) == 1
    assert rules[0]["name"] == "Rule A"


def test_list_rules_org_isolation(engine):
    engine.create_correlation_rule(ORG, {"name": "Rule A", "pattern": ["test"]})
    assert engine.list_correlation_rules(ORG2) == []


# ---------------------------------------------------------------------------
# Correlation run
# ---------------------------------------------------------------------------

def test_run_correlation_no_events(engine):
    engine.create_correlation_rule(ORG, {
        "name": "Test Rule",
        "pattern": ["login_failure"],
        "time_window_seconds": 300,
        "min_count": 2,
        "output_severity": "high",
    })
    result = engine.run_correlation(ORG)
    assert result == []


def test_run_correlation_matches(engine):
    engine.create_correlation_rule(ORG, {
        "name": "Brute Force",
        "pattern": ["login_failure"],
        "time_window_seconds": 3600,
        "min_count": 2,
        "output_severity": "critical",
    })
    engine.ingest_event(ORG, {"event_type": "login_failure", "severity": "medium"})
    engine.ingest_event(ORG, {"event_type": "login_failure", "severity": "medium"})
    engine.ingest_event(ORG, {"event_type": "login_failure", "severity": "medium"})

    matches = engine.run_correlation(ORG)
    assert len(matches) == 1
    assert matches[0]["rule_name"] == "Brute Force"
    assert matches[0]["severity"] == "critical"
    assert matches[0]["event_count"] >= 2
    assert len(matches[0]["matched_event_ids"]) >= 2


def test_run_correlation_no_rules(engine):
    engine.ingest_event(ORG, {"event_type": "login_failure", "severity": "medium"})
    result = engine.run_correlation(ORG)
    assert result == []


# ---------------------------------------------------------------------------
# Correlated incidents
# ---------------------------------------------------------------------------

def test_create_incident_basic(engine):
    incident = engine.create_correlated_incident(ORG, {
        "rule_id": "rule-123",
        "matched_event_ids": ["evt-1", "evt-2"],
        "title": "Brute Force Attack Detected",
        "severity": "high",
    })
    assert incident["id"]
    assert incident["rule_id"] == "rule-123"
    assert incident["matched_event_ids"] == ["evt-1", "evt-2"]
    assert incident["title"] == "Brute Force Attack Detected"
    assert incident["severity"] == "high"
    assert incident["status"] == "open"


def test_create_incident_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.create_correlated_incident(ORG, {"severity": "extreme"})


def test_list_incidents_empty(engine):
    assert engine.list_correlated_incidents(ORG) == []


def test_list_incidents_returns_created(engine):
    engine.create_correlated_incident(ORG, {
        "title": "Test Incident",
        "severity": "medium",
        "matched_event_ids": [],
    })
    incidents = engine.list_correlated_incidents(ORG)
    assert len(incidents) == 1
    assert incidents[0]["title"] == "Test Incident"


def test_list_incidents_filter_status(engine):
    engine.create_correlated_incident(ORG, {"title": "Open", "severity": "low", "matched_event_ids": []})
    open_incidents = engine.list_correlated_incidents(ORG, status="open")
    assert len(open_incidents) == 1
    resolved = engine.list_correlated_incidents(ORG, status="resolved")
    assert resolved == []


def test_list_incidents_org_isolation(engine):
    engine.create_correlated_incident(ORG, {"title": "Incident", "severity": "high", "matched_event_ids": []})
    assert engine.list_correlated_incidents(ORG2) == []


def test_list_incidents_limit(engine):
    for i in range(5):
        engine.create_correlated_incident(ORG, {"title": f"Inc {i}", "severity": "low", "matched_event_ids": []})
    result = engine.list_correlated_incidents(ORG, limit=3)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine):
    stats = engine.get_correlation_stats(ORG)
    assert stats["org_id"] == ORG
    assert stats["events_ingested"] == 0
    assert stats["rules"] == 0
    assert stats["incidents_created"] == 0
    assert stats["correlation_rate"] == 0.0


def test_get_stats_populated(engine):
    engine.ingest_event(ORG, {"event_type": "test", "severity": "low"})
    engine.ingest_event(ORG, {"event_type": "test", "severity": "low"})
    engine.create_correlation_rule(ORG, {"name": "Rule", "pattern": ["test"]})
    engine.create_correlated_incident(ORG, {"title": "Inc", "severity": "low", "matched_event_ids": []})
    stats = engine.get_correlation_stats(ORG)
    assert stats["events_ingested"] == 2
    assert stats["rules"] == 1
    assert stats["incidents_created"] == 1
    assert stats["correlation_rate"] == 0.5


def test_get_stats_org_isolation(engine):
    engine.ingest_event(ORG, {"event_type": "test", "severity": "low"})
    stats = engine.get_correlation_stats(ORG2)
    assert stats["events_ingested"] == 0
