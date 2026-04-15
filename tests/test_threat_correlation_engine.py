"""Tests for ThreatCorrelationEngine — 32 tests covering:
- DB init and schema
- Rule creation and listing
- Signal ingestion (valid, invalid signal_type, invalid severity)
- Auto-correlation: incident created when min_signals threshold met
- Auto-correlation: no incident below threshold
- Severity threshold filtering
- Signal type filtering in rules
- Incident lifecycle (list, get with timeline, resolve)
- Stats aggregation
- Org isolation
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.threat_correlation_engine import ThreatCorrelationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    """Fresh ThreatCorrelationEngine backed by a temp SQLite DB."""
    return ThreatCorrelationEngine(db_path=str(tmp_path / "threat_corr_test.db"))


@pytest.fixture
def org():
    return f"org-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def org2():
    return f"org2-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def basic_rule_data():
    return {
        "rule_name": "Brute Force Detection",
        "signal_types": ["alert"],
        "time_window_minutes": 60,
        "min_signals": 3,
        "severity_threshold": "medium",
        "correlation_field": "src_ip",
        "auto_create_incident": True,
        "mitre_tactic": "TA0006",
        "enabled": True,
    }


@pytest.fixture
def rule(engine, org, basic_rule_data):
    return engine.create_rule(org, basic_rule_data)


# ---------------------------------------------------------------------------
# DB init
# ---------------------------------------------------------------------------

def test_engine_initializes(engine):
    assert engine is not None


def test_db_file_created(tmp_path):
    db_path = str(tmp_path / "init_test.db")
    e = ThreatCorrelationEngine(db_path=db_path)
    assert Path(db_path).exists()


def test_db_tables_created(engine):
    import sqlite3
    conn = sqlite3.connect(engine.db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "correlation_rules" in tables
    assert "threat_signals" in tables
    assert "correlated_incidents" in tables
    assert "correlation_timeline" in tables


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def test_create_rule_returns_dict(engine, org, basic_rule_data):
    rule = engine.create_rule(org, basic_rule_data)
    assert isinstance(rule, dict)
    assert "id" in rule
    assert rule["rule_name"] == "Brute Force Detection"


def test_create_rule_stores_signal_types_as_list(engine, org, basic_rule_data):
    rule = engine.create_rule(org, basic_rule_data)
    assert isinstance(rule["signal_types"], list)
    assert "alert" in rule["signal_types"]


def test_create_rule_invalid_severity_threshold(engine, org):
    with pytest.raises(ValueError, match="Invalid severity_threshold"):
        engine.create_rule(org, {"rule_name": "Bad", "severity_threshold": "extreme"})


def test_create_rule_missing_name(engine, org):
    with pytest.raises(ValueError, match="rule_name is required"):
        engine.create_rule(org, {"severity_threshold": "high"})


def test_list_rules_empty(engine, org):
    assert engine.list_rules(org) == []


def test_list_rules_returns_created(engine, org, rule):
    rules = engine.list_rules(org)
    assert len(rules) == 1
    assert rules[0]["rule_name"] == rule["rule_name"]


def test_list_rules_org_isolation(engine, org, org2, basic_rule_data):
    engine.create_rule(org, basic_rule_data)
    assert engine.list_rules(org2) == []


# ---------------------------------------------------------------------------
# Signal ingestion
# ---------------------------------------------------------------------------

def test_ingest_signal_returns_dict(engine, org):
    sig = engine.ingest_signal(org, {
        "signal_type": "alert",
        "source_engine": "edr",
        "entity_type": "ip",
        "entity_value": "1.2.3.4",
        "severity": "high",
        "description": "Suspicious process",
    })
    assert isinstance(sig, dict)
    assert "id" in sig
    assert sig["entity_value"] == "1.2.3.4"


def test_ingest_signal_invalid_type(engine, org):
    with pytest.raises(ValueError, match="Invalid signal_type"):
        engine.ingest_signal(org, {
            "signal_type": "unknown_type",
            "entity_value": "1.2.3.4",
        })


def test_ingest_signal_invalid_severity(engine, org):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.ingest_signal(org, {
            "signal_type": "alert",
            "entity_value": "1.2.3.4",
            "severity": "nuclear",
        })


def test_ingest_signal_sets_expires_at(engine, org):
    sig = engine.ingest_signal(org, {
        "signal_type": "ioc",
        "entity_value": "evil.com",
        "entity_type": "domain",
        "severity": "critical",
        "ttl_minutes": 60,
    })
    assert sig["expires_at"] is not None
    assert sig["ttl_minutes"] == 60


# ---------------------------------------------------------------------------
# List signals
# ---------------------------------------------------------------------------

def test_list_signals_empty(engine, org):
    assert engine.list_signals(org) == []


def test_list_signals_returns_ingested(engine, org):
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "1.1.1.1", "severity": "low"})
    signals = engine.list_signals(org)
    assert len(signals) == 1


def test_list_signals_filter_by_type(engine, org):
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "1.1.1.1", "severity": "low"})
    engine.ingest_signal(org, {"signal_type": "ioc", "entity_value": "evil.com", "severity": "high"})
    iocs = engine.list_signals(org, signal_type="ioc")
    assert len(iocs) == 1
    assert iocs[0]["signal_type"] == "ioc"


def test_list_signals_filter_by_entity(engine, org):
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "192.168.1.1", "severity": "medium"})
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "10.0.0.1", "severity": "low"})
    results = engine.list_signals(org, entity_value="192.168.1.1")
    assert len(results) == 1


def test_list_signals_filter_by_source_engine(engine, org):
    engine.ingest_signal(org, {"signal_type": "alert", "source_engine": "edr", "entity_value": "host1", "severity": "high"})
    engine.ingest_signal(org, {"signal_type": "alert", "source_engine": "siem", "entity_value": "host2", "severity": "low"})
    edr_sigs = engine.list_signals(org, source_engine="edr")
    assert all(s["source_engine"] == "edr" for s in edr_sigs)


def test_list_signals_org_isolation(engine, org, org2):
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "1.1.1.1", "severity": "low"})
    assert engine.list_signals(org2) == []


# ---------------------------------------------------------------------------
# Correlation — incident creation
# ---------------------------------------------------------------------------

def test_correlation_creates_incident_at_threshold(engine, org, basic_rule_data):
    """When min_signals signals arrive for same entity, incident is auto-created."""
    engine.create_rule(org, basic_rule_data)  # min_signals=3
    entity = "attacker-ip-192.168.1.100"
    for _ in range(3):
        engine.ingest_signal(org, {
            "signal_type": "alert",
            "source_engine": "edr",
            "entity_value": entity,
            "entity_type": "ip",
            "severity": "high",
        })
    incidents = engine.list_incidents(org)
    assert len(incidents) >= 1
    assert incidents[0]["entity_value"] == entity


def test_correlation_no_incident_below_threshold(engine, org, basic_rule_data):
    """Below min_signals, no incident is created."""
    engine.create_rule(org, basic_rule_data)  # min_signals=3
    entity = "safe-ip-10.0.0.1"
    for _ in range(2):  # Only 2, below threshold of 3
        engine.ingest_signal(org, {
            "signal_type": "alert",
            "entity_value": entity,
            "severity": "high",
        })
    incidents = engine.list_incidents(org)
    assert len(incidents) == 0


def test_correlation_skips_disabled_rule(engine, org):
    engine.create_rule(org, {
        "rule_name": "Disabled Rule",
        "signal_types": ["alert"],
        "min_signals": 1,
        "severity_threshold": "low",
        "enabled": False,
    })
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "1.2.3.4", "severity": "critical"})
    assert engine.list_incidents(org) == []


def test_correlation_severity_threshold_filtering(engine, org):
    """Signals below severity threshold should not trigger correlation."""
    engine.create_rule(org, {
        "rule_name": "High Sev Rule",
        "signal_types": [],
        "min_signals": 2,
        "severity_threshold": "high",
        "auto_create_incident": True,
        "enabled": True,
    })
    entity = "low-sev-host"
    for _ in range(5):
        engine.ingest_signal(org, {
            "signal_type": "alert",
            "entity_value": entity,
            "severity": "low",  # Below "high" threshold
        })
    assert engine.list_incidents(org) == []


def test_correlation_signal_references_incident(engine, org, basic_rule_data):
    """After threshold met, signal.correlated_incident_id is set."""
    engine.create_rule(org, basic_rule_data)
    entity = "corr-entity-99"
    signals = []
    for _ in range(3):
        sig = engine.ingest_signal(org, {
            "signal_type": "alert",
            "entity_value": entity,
            "severity": "high",
        })
        signals.append(sig)
    # Last signal should have correlated_incident_id set
    last_sig = signals[-1]
    assert last_sig.get("correlated_incident_id") is not None


def test_correlation_updates_existing_incident(engine, org, basic_rule_data):
    """Further signals increment signal_count on existing incident."""
    engine.create_rule(org, basic_rule_data)
    entity = "persistent-attacker"
    for _ in range(4):  # 3 creates incident, 4th updates it
        engine.ingest_signal(org, {
            "signal_type": "alert",
            "entity_value": entity,
            "severity": "high",
        })
    incidents = engine.list_incidents(org)
    # Should be only 1 incident for same entity+rule, not 2
    assert len(incidents) == 1


# ---------------------------------------------------------------------------
# Incident lifecycle
# ---------------------------------------------------------------------------

def test_list_incidents_empty(engine, org):
    assert engine.list_incidents(org) == []


def test_list_incidents_filter_by_status(engine, org, basic_rule_data):
    engine.create_rule(org, basic_rule_data)
    entity = "filter-test-ip"
    for _ in range(3):
        engine.ingest_signal(org, {"signal_type": "alert", "entity_value": entity, "severity": "high"})
    new_incidents = engine.list_incidents(org, status="new")
    assert len(new_incidents) >= 1


def test_list_incidents_filter_by_severity(engine, org, basic_rule_data):
    engine.create_rule(org, basic_rule_data)
    entity = "sev-filter-ip"
    for _ in range(3):
        engine.ingest_signal(org, {"signal_type": "alert", "entity_value": entity, "severity": "high"})
    high_incidents = engine.list_incidents(org, severity="high")
    assert len(high_incidents) >= 1


def test_get_incident_with_timeline(engine, org, basic_rule_data):
    engine.create_rule(org, basic_rule_data)
    entity = "timeline-host"
    for _ in range(3):
        engine.ingest_signal(org, {"signal_type": "alert", "entity_value": entity, "severity": "high"})
    incidents = engine.list_incidents(org)
    assert len(incidents) >= 1
    incident_id = incidents[0]["id"]
    full = engine.get_incident(org, incident_id)
    assert full is not None
    assert "timeline" in full
    assert isinstance(full["timeline"], list)


def test_get_incident_not_found(engine, org):
    result = engine.get_incident(org, "nonexistent-id")
    assert result is None


def test_resolve_incident(engine, org, basic_rule_data):
    engine.create_rule(org, basic_rule_data)
    entity = "resolve-test-ip"
    for _ in range(3):
        engine.ingest_signal(org, {"signal_type": "alert", "entity_value": entity, "severity": "high"})
    incidents = engine.list_incidents(org)
    incident_id = incidents[0]["id"]
    ok = engine.resolve_incident(org, incident_id)
    assert ok is True
    resolved = engine.list_incidents(org, status="resolved")
    assert any(i["id"] == incident_id for i in resolved)


def test_resolve_incident_not_found(engine, org):
    result = engine.resolve_incident(org, "nonexistent-id")
    assert result is False


def test_incidents_org_isolation(engine, org, org2, basic_rule_data):
    engine.create_rule(org, basic_rule_data)
    entity = "shared-entity"
    for _ in range(3):
        engine.ingest_signal(org, {"signal_type": "alert", "entity_value": entity, "severity": "high"})
    assert engine.list_incidents(org2) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_correlation_stats_empty(engine, org):
    stats = engine.get_correlation_stats(org)
    assert stats["total_signals"] == 0
    assert stats["incidents_created"] == 0
    assert stats["correlation_rate"] == 0.0


def test_get_correlation_stats_counts_signals(engine, org):
    for _ in range(5):
        engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "1.2.3.4", "severity": "low"})
    stats = engine.get_correlation_stats(org)
    assert stats["total_signals"] == 5


def test_get_correlation_stats_signals_by_type(engine, org):
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "a", "severity": "low"})
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "b", "severity": "low"})
    engine.ingest_signal(org, {"signal_type": "ioc", "entity_value": "c", "severity": "medium"})
    stats = engine.get_correlation_stats(org)
    assert stats["signals_by_type"].get("alert", 0) == 2
    assert stats["signals_by_type"].get("ioc", 0) == 1


def test_get_correlation_stats_top_entities(engine, org):
    for _ in range(5):
        engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "top-ip", "severity": "low"})
    engine.ingest_signal(org, {"signal_type": "alert", "entity_value": "other-ip", "severity": "low"})
    stats = engine.get_correlation_stats(org)
    top = stats["top_entities"]
    assert isinstance(top, list)
    assert top[0]["entity"] == "top-ip"
    assert top[0]["count"] == 5


def test_get_correlation_stats_auto_created(engine, org, basic_rule_data):
    engine.create_rule(org, basic_rule_data)
    entity = "auto-stats-ip"
    for _ in range(3):
        engine.ingest_signal(org, {"signal_type": "alert", "entity_value": entity, "severity": "high"})
    stats = engine.get_correlation_stats(org)
    assert stats["incidents_created"] >= 1
    assert stats["auto_created"] >= 1
