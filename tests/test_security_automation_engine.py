"""Tests for SecurityAutomationEngine — 30+ tests covering all methods and stats."""

from __future__ import annotations

import pytest

from core.security_automation_engine import SecurityAutomationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_security_automation.db")


@pytest.fixture
def engine(db_path):
    return SecurityAutomationEngine(db_path=db_path)


ORG = "org-sa-test"
ORG2 = "org-sa-other"


# ---------------------------------------------------------------------------
# create_automation_rule
# ---------------------------------------------------------------------------

def test_create_rule_minimal(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Block Brute Force"})
    assert rule["name"] == "Block Brute Force"
    assert rule["trigger_type"] == "alert"
    assert rule["enabled"] is True
    assert rule["actions"] == []
    assert "id" in rule
    assert "created_at" in rule


def test_create_rule_all_fields(engine):
    rule = engine.create_automation_rule(ORG, {
        "name": "Nightly Scan",
        "trigger_type": "schedule",
        "trigger_condition": "0 2 * * *",
        "actions": [{"type": "scan", "target": "all"}],
        "enabled": True,
    })
    assert rule["trigger_type"] == "schedule"
    assert rule["trigger_condition"] == "0 2 * * *"
    assert rule["actions"] == [{"type": "scan", "target": "all"}]


def test_create_rule_webhook_trigger(engine):
    rule = engine.create_automation_rule(ORG, {
        "name": "Webhook Handler",
        "trigger_type": "webhook",
    })
    assert rule["trigger_type"] == "webhook"


def test_create_rule_disabled(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Disabled Rule", "enabled": False})
    assert rule["enabled"] is False


def test_create_rule_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_automation_rule(ORG, {})


def test_create_rule_invalid_trigger_type(engine):
    with pytest.raises(ValueError, match="Invalid trigger_type"):
        engine.create_automation_rule(ORG, {"name": "Bad", "trigger_type": "unknown"})


def test_create_rule_returns_unique_ids(engine):
    r1 = engine.create_automation_rule(ORG, {"name": "R1"})
    r2 = engine.create_automation_rule(ORG, {"name": "R2"})
    assert r1["id"] != r2["id"]


# ---------------------------------------------------------------------------
# list_automation_rules
# ---------------------------------------------------------------------------

def test_list_rules_empty(engine):
    assert engine.list_automation_rules(ORG) == []


def test_list_rules_returns_all(engine):
    engine.create_automation_rule(ORG, {"name": "A"})
    engine.create_automation_rule(ORG, {"name": "B"})
    rules = engine.list_automation_rules(ORG)
    assert len(rules) == 2


def test_list_rules_filter_enabled(engine):
    engine.create_automation_rule(ORG, {"name": "E", "enabled": True})
    engine.create_automation_rule(ORG, {"name": "D", "enabled": False})
    enabled = engine.list_automation_rules(ORG, enabled=True)
    assert all(r["enabled"] for r in enabled)
    disabled = engine.list_automation_rules(ORG, enabled=False)
    assert all(not r["enabled"] for r in disabled)


def test_list_rules_org_isolation(engine):
    engine.create_automation_rule(ORG, {"name": "Org1 Rule"})
    engine.create_automation_rule(ORG2, {"name": "Org2 Rule"})
    assert len(engine.list_automation_rules(ORG)) == 1
    assert len(engine.list_automation_rules(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_rule
# ---------------------------------------------------------------------------

def test_get_rule_found(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Findable"})
    fetched = engine.get_rule(ORG, rule["id"])
    assert fetched is not None
    assert fetched["name"] == "Findable"


def test_get_rule_not_found(engine):
    assert engine.get_rule(ORG, "nonexistent-id") is None


def test_get_rule_wrong_org(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Isolated"})
    assert engine.get_rule(ORG2, rule["id"]) is None


# ---------------------------------------------------------------------------
# enable_rule / disable_rule
# ---------------------------------------------------------------------------

def test_enable_rule(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Toggle", "enabled": False})
    updated = engine.enable_rule(ORG, rule["id"])
    assert updated["enabled"] is True


def test_disable_rule(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Active"})
    updated = engine.disable_rule(ORG, rule["id"])
    assert updated["enabled"] is False


def test_enable_rule_not_found(engine):
    assert engine.enable_rule(ORG, "ghost-id") is None


def test_disable_rule_not_found(engine):
    assert engine.disable_rule(ORG, "ghost-id") is None


def test_toggle_persists(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Toggler"})
    engine.disable_rule(ORG, rule["id"])
    engine.enable_rule(ORG, rule["id"])
    fetched = engine.get_rule(ORG, rule["id"])
    assert fetched["enabled"] is True


# ---------------------------------------------------------------------------
# execute_rule
# ---------------------------------------------------------------------------

def test_execute_rule_success(engine):
    rule = engine.create_automation_rule(ORG, {
        "name": "Executor",
        "actions": [{"type": "notify"}, {"type": "block_ip"}],
    })
    result = engine.execute_rule(ORG, rule["id"], {"alert_id": "a-123"})
    assert result is not None
    assert result["status"] == "success"
    assert len(result["actions_taken"]) == 2
    assert "duration_ms" in result
    assert "execution_id" in result


def test_execute_rule_no_actions(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Empty", "actions": []})
    result = engine.execute_rule(ORG, rule["id"], {})
    assert result["status"] == "success"
    assert result["actions_taken"] == []


def test_execute_rule_not_found(engine):
    assert engine.execute_rule(ORG, "ghost-rule", {}) is None


def test_execute_rule_context_preserved(engine):
    rule = engine.create_automation_rule(ORG, {
        "name": "Context Rule",
        "actions": [{"type": "enrich"}],
    })
    ctx = {"ip": "1.2.3.4", "severity": "high"}
    result = engine.execute_rule(ORG, rule["id"], ctx)
    assert result["context"] == ctx


# ---------------------------------------------------------------------------
# list_executions
# ---------------------------------------------------------------------------

def test_list_executions_empty(engine):
    assert engine.list_executions(ORG) == []


def test_list_executions_returns_history(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Exec R"})
    engine.execute_rule(ORG, rule["id"], {})
    engine.execute_rule(ORG, rule["id"], {})
    execs = engine.list_executions(ORG)
    assert len(execs) == 2


def test_list_executions_filter_rule_id(engine):
    r1 = engine.create_automation_rule(ORG, {"name": "R1"})
    r2 = engine.create_automation_rule(ORG, {"name": "R2"})
    engine.execute_rule(ORG, r1["id"], {})
    engine.execute_rule(ORG, r2["id"], {})
    execs = engine.list_executions(ORG, rule_id=r1["id"])
    assert len(execs) == 1
    assert execs[0]["rule_id"] == r1["id"]


def test_list_executions_filter_status(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Status Filter"})
    engine.execute_rule(ORG, rule["id"], {})
    execs = engine.list_executions(ORG, status="success")
    assert len(execs) == 1


def test_list_executions_limit(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Limiter"})
    for _ in range(5):
        engine.execute_rule(ORG, rule["id"], {})
    execs = engine.list_executions(ORG, limit=3)
    assert len(execs) == 3


# ---------------------------------------------------------------------------
# get_automation_stats
# ---------------------------------------------------------------------------

def test_stats_empty_org(engine):
    stats = engine.get_automation_stats(ORG)
    assert stats["total_rules"] == 0
    assert stats["enabled_rules"] == 0
    assert stats["executions_today"] == 0
    assert stats["total_executions"] == 0
    assert stats["success_rate"] == 0.0
    assert stats["avg_duration_ms"] == 0.0


def test_stats_counts_rules(engine):
    engine.create_automation_rule(ORG, {"name": "A"})
    engine.create_automation_rule(ORG, {"name": "B", "enabled": False})
    stats = engine.get_automation_stats(ORG)
    assert stats["total_rules"] == 2
    assert stats["enabled_rules"] == 1


def test_stats_execution_counts(engine):
    rule = engine.create_automation_rule(ORG, {"name": "R"})
    engine.execute_rule(ORG, rule["id"], {})
    engine.execute_rule(ORG, rule["id"], {})
    stats = engine.get_automation_stats(ORG)
    assert stats["total_executions"] == 2
    assert stats["executions_today"] == 2
    assert stats["success_rate"] == 100.0


def test_stats_avg_duration_ms(engine):
    rule = engine.create_automation_rule(ORG, {"name": "Timed"})
    engine.execute_rule(ORG, rule["id"], {})
    stats = engine.get_automation_stats(ORG)
    assert stats["avg_duration_ms"] >= 0.0
