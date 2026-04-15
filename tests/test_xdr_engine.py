"""Tests for XDREngine — Extended Detection & Response Correlation Engine.

25+ tests covering org isolation, signal ingestion, auto-correlation,
incident CRUD, signal linking, correlation rules, and stats.
"""

from __future__ import annotations

import os
import pytest

from core.xdr_engine import XDREngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_xdr.db")
    return XDREngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# Schema / init
# ---------------------------------------------------------------------------


def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "xdr.db")
    e = XDREngine(db_path=db)
    assert os.path.exists(db)


# ---------------------------------------------------------------------------
# Signal ingestion
# ---------------------------------------------------------------------------


def test_ingest_signal_returns_dict(engine):
    result = engine.ingest_signal(ORG_A, {
        "source_type": "endpoint",
        "signal_type": "malware",
        "severity": "high",
        "entity_id": "host-001",
        "entity_type": "host",
    })
    assert "signal_id" in result
    assert result["org_id"] == ORG_A
    assert result["signal_type"] == "malware"


def test_ingest_signal_stores_raw_data(engine):
    raw = {"process": "cmd.exe", "pid": 1234}
    result = engine.ingest_signal(ORG_A, {
        "source_type": "endpoint",
        "entity_id": "host-002",
        "raw_data": raw,
    })
    assert result["raw_data"]["process"] == "cmd.exe"


def test_ingest_signal_defaults(engine):
    result = engine.ingest_signal(ORG_A, {})
    assert result["source_type"] == "endpoint"
    assert result["severity"] == "medium"
    assert result["confidence"] == 0.8


def test_ingest_signal_org_isolation(engine):
    engine.ingest_signal(ORG_A, {"entity_id": "host-a"})
    engine.ingest_signal(ORG_B, {"entity_id": "host-b"})
    sigs_a = engine.list_signals(ORG_A)
    sigs_b = engine.list_signals(ORG_B)
    assert all(s["org_id"] == ORG_A for s in sigs_a)
    assert len(sigs_a) == 1
    assert len(sigs_b) == 1


# ---------------------------------------------------------------------------
# Auto-correlation
# ---------------------------------------------------------------------------


def test_auto_correlation_creates_incident(engine):
    """Two signals for the same entity_id within 24h → auto-incident."""
    entity = "suspicious-host-01"
    engine.ingest_signal(ORG_A, {"entity_id": entity, "signal_type": "malware", "severity": "high"})
    engine.ingest_signal(ORG_A, {"entity_id": entity, "signal_type": "lateral_movement", "severity": "medium"})

    incidents = engine.list_incidents(ORG_A)
    assert len(incidents) >= 1
    # The incident should reference the entity
    inc = incidents[0]
    assert entity in inc["affected_entities"] or entity in str(inc)


def test_auto_correlation_no_incident_single_signal(engine):
    """A single signal should NOT auto-create an incident."""
    engine.ingest_signal(ORG_A, {"entity_id": "lonely-host", "signal_type": "anomaly"})
    incidents = engine.list_incidents(ORG_A)
    assert len(incidents) == 0


def test_auto_correlation_org_isolation(engine):
    entity = "shared-entity-ip"
    # Two signals in ORG_A → incident in ORG_A
    engine.ingest_signal(ORG_A, {"entity_id": entity, "signal_type": "malware"})
    engine.ingest_signal(ORG_A, {"entity_id": entity, "signal_type": "c2"})
    # ORG_B should have no incidents
    assert len(engine.list_incidents(ORG_B)) == 0


# ---------------------------------------------------------------------------
# List signals
# ---------------------------------------------------------------------------


def test_list_signals_filter_source_type(engine):
    engine.ingest_signal(ORG_A, {"source_type": "network", "entity_id": "ip-1"})
    engine.ingest_signal(ORG_A, {"source_type": "endpoint", "entity_id": "host-1"})
    net_sigs = engine.list_signals(ORG_A, source_type="network")
    assert all(s["source_type"] == "network" for s in net_sigs)


def test_list_signals_filter_severity(engine):
    engine.ingest_signal(ORG_A, {"severity": "critical", "entity_id": "h1"})
    engine.ingest_signal(ORG_A, {"severity": "low", "entity_id": "h2"})
    crits = engine.list_signals(ORG_A, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


def test_list_signals_limit(engine):
    for i in range(10):
        engine.ingest_signal(ORG_A, {"entity_id": f"host-{i}"})
    result = engine.list_signals(ORG_A, limit=3)
    assert len(result) <= 3


def test_list_signals_raw_data_deserialized(engine):
    engine.ingest_signal(ORG_A, {"entity_id": "h1", "raw_data": {"key": "value"}})
    sigs = engine.list_signals(ORG_A)
    assert isinstance(sigs[0]["raw_data"], dict)


# ---------------------------------------------------------------------------
# Incident CRUD
# ---------------------------------------------------------------------------


def test_create_incident(engine):
    inc = engine.create_incident(ORG_A, {
        "title": "Ransomware Campaign",
        "description": "Detected encryption activity",
        "attack_stage": "impact",
        "severity": "critical",
        "affected_entities": ["host-01", "host-02"],
    })
    assert "incident_id" in inc
    assert inc["severity"] == "critical"
    assert inc["attack_stage"] == "impact"


def test_create_incident_affected_entities_deserialized(engine):
    inc = engine.create_incident(ORG_A, {
        "title": "Test",
        "affected_entities": ["user-abc"],
    })
    assert isinstance(inc["affected_entities"], list)
    assert "user-abc" in inc["affected_entities"]


def test_list_incidents_filter_status(engine):
    engine.create_incident(ORG_A, {"title": "Inc1", "status": "new"})
    engine.create_incident(ORG_A, {"title": "Inc2", "status": "investigating"})
    new_incs = engine.list_incidents(ORG_A, status="new")
    assert all(i["status"] == "new" for i in new_incs)


def test_list_incidents_filter_severity(engine):
    engine.create_incident(ORG_A, {"title": "Crit", "severity": "critical"})
    engine.create_incident(ORG_A, {"title": "Low", "severity": "low"})
    crits = engine.list_incidents(ORG_A, severity="critical")
    assert len(crits) == 1


def test_list_incidents_filter_attack_stage(engine):
    engine.create_incident(ORG_A, {"title": "Exfil", "attack_stage": "exfiltration"})
    engine.create_incident(ORG_A, {"title": "Recon", "attack_stage": "discovery"})
    exfil = engine.list_incidents(ORG_A, attack_stage="exfiltration")
    assert len(exfil) == 1


def test_get_incident_with_signals(engine):
    inc = engine.create_incident(ORG_A, {"title": "With Signals"})
    sig = engine.ingest_signal(ORG_A, {"entity_id": "host-x"})
    engine.link_signal_to_incident(ORG_A, inc["incident_id"], sig["signal_id"])

    full = engine.get_incident(ORG_A, inc["incident_id"])
    assert full is not None
    assert len(full["signals"]) == 1
    assert full["signals"][0]["signal_id"] == sig["signal_id"]


def test_get_incident_not_found(engine):
    result = engine.get_incident(ORG_A, "nonexistent-id")
    assert result is None


def test_get_incident_org_isolation(engine):
    inc = engine.create_incident(ORG_A, {"title": "Private"})
    result = engine.get_incident(ORG_B, inc["incident_id"])
    assert result is None


def test_update_incident_status(engine):
    inc = engine.create_incident(ORG_A, {"title": "Active"})
    ok = engine.update_incident_status(ORG_A, inc["incident_id"], "investigating")
    assert ok is True
    updated = engine.get_incident(ORG_A, inc["incident_id"])
    assert updated["status"] == "investigating"


def test_update_incident_status_with_assignee(engine):
    inc = engine.create_incident(ORG_A, {"title": "Assign Me"})
    ok = engine.update_incident_status(
        ORG_A, inc["incident_id"], "investigating", assigned_to="analyst@acme.com"
    )
    assert ok is True
    full = engine.get_incident(ORG_A, inc["incident_id"])
    assert full["assigned_to"] == "analyst@acme.com"


def test_update_incident_status_invalid_raises(engine):
    inc = engine.create_incident(ORG_A, {"title": "Bad Status"})
    with pytest.raises(ValueError, match="Invalid incident status"):
        engine.update_incident_status(ORG_A, inc["incident_id"], "snoozed")


def test_update_incident_status_wrong_org(engine):
    inc = engine.create_incident(ORG_A, {"title": "Org A Inc"})
    ok = engine.update_incident_status(ORG_B, inc["incident_id"], "resolved")
    assert ok is False


# ---------------------------------------------------------------------------
# Signal linking
# ---------------------------------------------------------------------------


def test_link_signal_to_incident(engine):
    inc = engine.create_incident(ORG_A, {"title": "Link Test"})
    sig = engine.ingest_signal(ORG_A, {"entity_id": "host-link"})
    ok = engine.link_signal_to_incident(ORG_A, inc["incident_id"], sig["signal_id"])
    assert ok is True


def test_link_signal_increments_signal_count(engine):
    inc = engine.create_incident(ORG_A, {"title": "Count Test"})
    sig = engine.ingest_signal(ORG_A, {"entity_id": "host-count"})
    engine.link_signal_to_incident(ORG_A, inc["incident_id"], sig["signal_id"])
    full = engine.get_incident(ORG_A, inc["incident_id"])
    assert full["signal_count"] >= 1


def test_link_signal_updates_affected_entities(engine):
    inc = engine.create_incident(ORG_A, {"title": "Entity Merge"})
    sig = engine.ingest_signal(ORG_A, {"entity_id": "new-entity-99"})
    engine.link_signal_to_incident(ORG_A, inc["incident_id"], sig["signal_id"])
    full = engine.get_incident(ORG_A, inc["incident_id"])
    assert "new-entity-99" in full["affected_entities"]


def test_link_signal_wrong_incident(engine):
    sig = engine.ingest_signal(ORG_A, {"entity_id": "host-x"})
    ok = engine.link_signal_to_incident(ORG_A, "nonexistent-incident", sig["signal_id"])
    assert ok is False


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------


def test_create_rule(engine):
    rule = engine.create_rule(ORG_A, {
        "name": "Lateral + Credential Theft",
        "description": "Detect combined lateral movement and credential theft",
        "conditions": {
            "signal_types": ["lateral_movement", "credential_theft"],
            "min_signals": 2,
            "time_window_hours": 24,
        },
        "incident_severity": "high",
        "mitre_tactic": "TA0008",
    })
    assert "rule_id" in rule
    assert rule["name"] == "Lateral + Credential Theft"
    assert isinstance(rule["conditions"], dict)


def test_list_rules_enabled_only(engine):
    engine.create_rule(ORG_A, {"name": "Enabled Rule", "enabled": 1})
    engine.create_rule(ORG_A, {"name": "Disabled Rule", "enabled": 0})
    rules = engine.list_rules(ORG_A, enabled_only=True)
    assert all(r["enabled"] == 1 for r in rules)
    assert len(rules) == 1


def test_list_rules_all(engine):
    engine.create_rule(ORG_A, {"name": "Rule1", "enabled": 1})
    engine.create_rule(ORG_A, {"name": "Rule2", "enabled": 0})
    all_rules = engine.list_rules(ORG_A, enabled_only=False)
    assert len(all_rules) == 2


def test_list_rules_conditions_deserialized(engine):
    conds = {"min_signals": 3, "time_window_hours": 6}
    engine.create_rule(ORG_A, {"name": "Deserialized", "conditions": conds})
    rules = engine.list_rules(ORG_A)
    assert isinstance(rules[0]["conditions"], dict)
    assert rules[0]["conditions"]["min_signals"] == 3


def test_list_rules_org_isolation(engine):
    engine.create_rule(ORG_A, {"name": "Org A Rule"})
    rules_b = engine.list_rules(ORG_B)
    assert len(rules_b) == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_xdr_stats_empty(engine):
    stats = engine.get_xdr_stats(ORG_A)
    assert stats["total_signals"] == 0
    assert stats["new_incidents"] == 0
    assert stats["active_incidents"] == 0
    assert stats["critical_incidents"] == 0
    assert stats["signals_last_24h"] == 0


def test_get_xdr_stats_populated(engine):
    engine.ingest_signal(ORG_A, {"source_type": "network", "severity": "high", "entity_id": "h1"})
    engine.ingest_signal(ORG_A, {"source_type": "endpoint", "severity": "critical", "entity_id": "h1"})
    engine.create_incident(ORG_A, {"title": "Crit Inc", "severity": "critical", "status": "new"})

    stats = engine.get_xdr_stats(ORG_A)
    assert stats["total_signals"] == 2
    assert "network" in stats["by_source"]
    assert "endpoint" in stats["by_source"]
    assert stats["critical_incidents"] >= 1
    assert stats["signals_last_24h"] == 2


def test_get_xdr_stats_org_isolation(engine):
    engine.ingest_signal(ORG_A, {"entity_id": "h1"})
    stats_b = engine.get_xdr_stats(ORG_B)
    assert stats_b["total_signals"] == 0
