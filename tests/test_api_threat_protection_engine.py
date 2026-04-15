"""Tests for APIThreatProtectionEngine — 35 tests."""
from __future__ import annotations

import pytest
from core.api_threat_protection_engine import (
    APIThreatProtectionEngine,
    VALID_THREAT_TYPES,
    VALID_ACTIONS,
    VALID_RULE_STATUSES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return APIThreatProtectionEngine(db_path=str(tmp_path / "atp_test.db"))


def _rule(engine, org_id="org1", name="Block SQLi", threat_type="injection", action="block", **kwargs):
    data = {"name": name, "threat_type": threat_type, "action": action, **kwargs}
    return engine.create_protection_rule(org_id, data)


def _event(engine, org_id="org1", threat_type="injection", source_ip="1.2.3.4", **kwargs):
    data = {"threat_type": threat_type, "source_ip": source_ip, **kwargs}
    return engine.record_threat_event(org_id, data)


# ---------------------------------------------------------------------------
# create_protection_rule
# ---------------------------------------------------------------------------

def test_create_rule_returns_record(engine):
    rule = _rule(engine)
    assert rule["name"] == "Block SQLi"
    assert rule["threat_type"] == "injection"
    assert rule["action"] == "block"
    assert rule["status"] == "active"
    assert rule["triggered_count"] == 0
    assert "id" in rule
    assert "created_at" in rule


def test_create_rule_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_protection_rule("org1", {"threat_type": "injection", "action": "block"})


def test_create_rule_invalid_threat_type_raises(engine):
    with pytest.raises(ValueError, match="threat_type"):
        engine.create_protection_rule("org1", {"name": "Rule", "threat_type": "xss"})


def test_create_rule_invalid_action_raises(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_protection_rule("org1", {"name": "Rule", "threat_type": "injection", "action": "delete"})


def test_create_rule_all_valid_threat_types(engine):
    for i, tt in enumerate(sorted(VALID_THREAT_TYPES)):
        rule = _rule(engine, name=f"Rule-{i}", threat_type=tt)
        assert rule["threat_type"] == tt


def test_create_rule_all_valid_actions(engine):
    for i, act in enumerate(sorted(VALID_ACTIONS)):
        rule = _rule(engine, name=f"ActRule-{i}", action=act)
        assert rule["action"] == act


def test_create_rule_custom_threshold_and_window(engine):
    rule = _rule(engine, threshold=100, window_seconds=300)
    assert rule["threshold"] == 100
    assert rule["window_seconds"] == 300


def test_create_rule_with_pattern(engine):
    rule = _rule(engine, pattern=r"(?i)(select|union|drop)")
    assert "select" in rule["pattern"]


# ---------------------------------------------------------------------------
# list_rules / get_rule
# ---------------------------------------------------------------------------

def test_list_rules_empty(engine):
    assert engine.list_rules("org1") == []


def test_list_rules_returns_all(engine):
    _rule(engine, name="R1", threat_type="injection")
    _rule(engine, name="R2", threat_type="bot_attack")
    assert len(engine.list_rules("org1")) == 2


def test_list_rules_threat_type_filter(engine):
    _rule(engine, name="R1", threat_type="injection")
    _rule(engine, name="R2", threat_type="bot_attack")
    inj = engine.list_rules("org1", threat_type="injection")
    assert len(inj) == 1
    assert inj[0]["threat_type"] == "injection"


def test_list_rules_status_filter(engine):
    r1 = _rule(engine, name="R1")
    _rule(engine, name="R2")
    engine.update_rule_status("org1", r1["id"], "disabled")
    active = engine.list_rules("org1", status="active")
    assert len(active) == 1


def test_list_rules_org_isolation(engine):
    _rule(engine, org_id="org1", name="R1")
    _rule(engine, org_id="org2", name="R2")
    assert len(engine.list_rules("org1")) == 1
    assert len(engine.list_rules("org2")) == 1


def test_get_rule_returns_record(engine):
    created = _rule(engine)
    fetched = engine.get_rule("org1", created["id"])
    assert fetched["id"] == created["id"]


def test_get_rule_wrong_org_returns_none(engine):
    created = _rule(engine, org_id="org1")
    assert engine.get_rule("org2", created["id"]) is None


def test_get_rule_nonexistent_returns_none(engine):
    assert engine.get_rule("org1", "no-such-id") is None


# ---------------------------------------------------------------------------
# update_rule_status
# ---------------------------------------------------------------------------

def test_update_rule_status_to_disabled(engine):
    rule = _rule(engine)
    result = engine.update_rule_status("org1", rule["id"], "disabled")
    assert result["status"] == "disabled"


def test_update_rule_status_to_testing(engine):
    rule = _rule(engine)
    result = engine.update_rule_status("org1", rule["id"], "testing")
    assert result["status"] == "testing"


def test_update_rule_invalid_status_raises(engine):
    rule = _rule(engine)
    with pytest.raises(ValueError, match="status"):
        engine.update_rule_status("org1", rule["id"], "archived")


def test_update_rule_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.update_rule_status("org1", "no-such-id", "disabled")


def test_update_rule_status_all_valid(engine):
    for i, st in enumerate(sorted(VALID_RULE_STATUSES)):
        rule = _rule(engine, name=f"StatusRule-{i}")
        result = engine.update_rule_status("org1", rule["id"], st)
        assert result["status"] == st


# ---------------------------------------------------------------------------
# record_threat_event
# ---------------------------------------------------------------------------

def test_record_event_returns_record(engine):
    ev = _event(engine)
    assert ev["threat_type"] == "injection"
    assert ev["source_ip"] == "1.2.3.4"
    assert ev["action_taken"] == "monitor"
    assert "id" in ev
    assert "detected_at" in ev


def test_record_event_invalid_threat_type_raises(engine):
    with pytest.raises(ValueError, match="threat_type"):
        engine.record_threat_event("org1", {"threat_type": "xss"})


def test_record_event_increments_rule_triggered_count(engine):
    rule = _rule(engine)
    _event(engine, rule_id=rule["id"])
    _event(engine, rule_id=rule["id"])
    updated = engine.get_rule("org1", rule["id"])
    assert updated["triggered_count"] == 2


def test_record_event_no_rule_id_no_error(engine):
    ev = _event(engine, rule_id="")
    assert ev["rule_id"] == ""


def test_record_event_all_threat_types(engine):
    for tt in sorted(VALID_THREAT_TYPES):
        ev = engine.record_threat_event("org1", {"threat_type": tt, "source_ip": "5.6.7.8"})
        assert ev["threat_type"] == tt


def test_record_event_org_isolation(engine):
    _event(engine, org_id="org1")
    _event(engine, org_id="org2")
    assert len(engine.list_threat_events("org1")) == 1
    assert len(engine.list_threat_events("org2")) == 1


# ---------------------------------------------------------------------------
# list_threat_events
# ---------------------------------------------------------------------------

def test_list_events_empty(engine):
    assert engine.list_threat_events("org1") == []


def test_list_events_returns_all(engine):
    _event(engine, threat_type="injection")
    _event(engine, threat_type="bot_attack")
    assert len(engine.list_threat_events("org1")) == 2


def test_list_events_threat_type_filter(engine):
    _event(engine, threat_type="injection")
    _event(engine, threat_type="bot_attack")
    inj = engine.list_threat_events("org1", threat_type="injection")
    assert len(inj) == 1 and inj[0]["threat_type"] == "injection"


def test_list_events_source_ip_filter(engine):
    _event(engine, source_ip="10.0.0.1")
    _event(engine, source_ip="10.0.0.2")
    result = engine.list_threat_events("org1", source_ip="10.0.0.1")
    assert len(result) == 1 and result[0]["source_ip"] == "10.0.0.1"


def test_list_events_rule_id_filter(engine):
    rule = _rule(engine)
    _event(engine, rule_id=rule["id"])
    _event(engine, rule_id="")
    result = engine.list_threat_events("org1", rule_id=rule["id"])
    assert len(result) == 1


def test_list_events_ordered_desc(engine):
    for i in range(3):
        _event(engine, threat_type="injection")
    events = engine.list_threat_events("org1")
    timestamps = [e["detected_at"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


# ---------------------------------------------------------------------------
# get_protection_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine):
    stats = engine.get_protection_stats("org1")
    assert stats["total_rules"] == 0
    assert stats["active_rules"] == 0
    assert stats["total_events"] == 0
    assert stats["events_today"] == 0
    assert stats["blocked_count"] == 0
    assert stats["by_threat_type"] == {}
    assert stats["top_attacker_ip"] is None


def test_get_stats_counts(engine):
    rule = _rule(engine)
    _event(engine, rule_id=rule["id"], threat_type="injection", action_taken="block", source_ip="1.1.1.1")
    _event(engine, threat_type="bot_attack", action_taken="monitor", source_ip="2.2.2.2")
    stats = engine.get_protection_stats("org1")
    assert stats["total_rules"] == 1
    assert stats["active_rules"] == 1
    assert stats["total_events"] == 2
    assert stats["blocked_count"] == 1
    assert stats["by_threat_type"]["injection"] == 1
    assert stats["by_threat_type"]["bot_attack"] == 1


def test_get_stats_events_today(engine):
    _event(engine)
    stats = engine.get_protection_stats("org1")
    assert stats["events_today"] == 1


def test_get_stats_top_attacker_ip(engine):
    _event(engine, source_ip="evil.host")
    _event(engine, source_ip="evil.host")
    _event(engine, source_ip="other.host")
    stats = engine.get_protection_stats("org1")
    assert stats["top_attacker_ip"] == "evil.host"


def test_get_stats_active_vs_disabled(engine):
    r1 = _rule(engine, name="R1")
    _rule(engine, name="R2")
    engine.update_rule_status("org1", r1["id"], "disabled")
    stats = engine.get_protection_stats("org1")
    assert stats["total_rules"] == 2
    assert stats["active_rules"] == 1


def test_get_stats_org_isolation(engine):
    _rule(engine, org_id="orgA")
    _event(engine, org_id="orgA")
    stats_a = engine.get_protection_stats("orgA")
    stats_b = engine.get_protection_stats("orgB")
    assert stats_a["total_rules"] == 1
    assert stats_b["total_rules"] == 0
    assert stats_a["total_events"] == 1
    assert stats_b["total_events"] == 0
