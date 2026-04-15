"""Tests for AlertingNotificationEngine.

Covers policy CRUD, alert lifecycle (trigger/acknowledge/resolve),
history queries, and statistics.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.alerting_notification_engine import AlertingNotificationEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "alerting_test.db")
    return AlertingNotificationEngine(db_path=db)


@pytest.fixture()
def policy(engine):
    return engine.create_alert_policy("org1", {
        "name": "CPU Threshold",
        "severity": "high",
        "condition_type": "threshold",
        "channels": ["email", "slack"],
        "enabled": True,
    })


@pytest.fixture()
def alert(engine, policy):
    return engine.trigger_alert("org1", {
        "policy_id": policy["policy_id"],
        "source_engine": "metrics_engine",
        "source_id": "cpu-001",
        "title": "CPU usage critical",
        "message": "CPU exceeded 95% for 5 minutes",
        "severity": "high",
        "context": {"host": "web-01", "value": 97},
    })


# ===========================================================================
# 1. Initialisation
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "alert_init.db")
    AlertingNotificationEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "alert_idem.db")
    AlertingNotificationEngine(db_path=db)
    AlertingNotificationEngine(db_path=db)


# ===========================================================================
# 2. Alert Policy CRUD
# ===========================================================================

def test_create_policy_returns_dict(engine):
    pol = engine.create_alert_policy("org1", {
        "name": "Anomaly Detection",
        "severity": "critical",
        "condition_type": "anomaly",
        "channels": ["pagerduty"],
        "enabled": True,
    })
    assert pol["policy_id"]
    assert pol["name"] == "Anomaly Detection"
    assert pol["severity"] == "critical"
    assert "pagerduty" in pol["channels"]
    assert pol["enabled"] is True


def test_create_policy_defaults(engine):
    pol = engine.create_alert_policy("org1", {"name": "Minimal"})
    assert pol["severity"] == "medium"
    assert pol["condition_type"] == "threshold"
    assert pol["channels"] == ["email"]
    assert pol["enabled"] is True


def test_create_policy_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.create_alert_policy("org1", {"name": "Bad", "severity": "fatal"})


def test_create_policy_invalid_condition_type(engine):
    with pytest.raises(ValueError, match="condition_type"):
        engine.create_alert_policy("org1", {"name": "Bad", "condition_type": "magic"})


def test_create_policy_invalid_channel(engine):
    with pytest.raises(ValueError, match="channels"):
        engine.create_alert_policy("org1", {"name": "Bad", "channels": ["twitter"]})


def test_list_policies_empty(engine):
    assert engine.list_alert_policies("org1") == []


def test_list_policies_returns_all(engine, policy):
    engine.create_alert_policy("org1", {"name": "Second"})
    result = engine.list_alert_policies("org1")
    assert len(result) == 2


def test_list_policies_filter_enabled(engine):
    engine.create_alert_policy("org1", {"name": "Active", "enabled": True})
    engine.create_alert_policy("org1", {"name": "Disabled", "enabled": False})
    active = engine.list_alert_policies("org1", enabled=True)
    disabled = engine.list_alert_policies("org1", enabled=False)
    assert all(p["enabled"] for p in active)
    assert all(not p["enabled"] for p in disabled)


def test_list_policies_org_isolation(engine, policy):
    assert engine.list_alert_policies("org2") == []


# ===========================================================================
# 3. Trigger Alert
# ===========================================================================

def test_trigger_alert_returns_dict(engine, alert):
    assert alert["alert_id"]
    assert alert["title"] == "CPU usage critical"
    assert alert["status"] == "open"
    assert alert["severity"] == "high"


def test_trigger_alert_context_preserved(engine, alert):
    assert alert["context"]["host"] == "web-01"
    assert alert["context"]["value"] == 97


def test_trigger_alert_defaults(engine):
    a = engine.trigger_alert("org1", {"title": "Min", "message": "msg"})
    assert a["severity"] == "medium"
    assert a["status"] == "open"
    assert a["policy_id"] == ""


def test_trigger_alert_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.trigger_alert("org1", {"title": "X", "message": "Y", "severity": "unknown"})


def test_list_alerts_empty(engine):
    assert engine.list_alerts("org1") == []


def test_list_alerts_returns_triggered(engine, alert):
    result = engine.list_alerts("org1")
    assert len(result) == 1
    assert result[0]["alert_id"] == alert["alert_id"]


def test_list_alerts_filter_severity(engine, alert):
    engine.trigger_alert("org1", {"title": "Low", "message": "m", "severity": "low"})
    high_only = engine.list_alerts("org1", severity="high")
    assert all(a["severity"] == "high" for a in high_only)


def test_list_alerts_filter_status(engine, alert):
    engine.trigger_alert("org1", {"title": "Another", "message": "m"})
    open_alerts = engine.list_alerts("org1", status="open")
    assert len(open_alerts) == 2


def test_list_alerts_limit(engine):
    for i in range(10):
        engine.trigger_alert("org1", {"title": f"Alert {i}", "message": "m"})
    result = engine.list_alerts("org1", limit=5)
    assert len(result) == 5


def test_list_alerts_org_isolation(engine, alert):
    assert engine.list_alerts("org2") == []


# ===========================================================================
# 4. Acknowledge Alert
# ===========================================================================

def test_acknowledge_alert(engine, alert):
    ack = engine.acknowledge_alert("org1", alert["alert_id"], "alice")
    assert ack["status"] == "acknowledged"
    assert ack["acknowledged_by"] == "alice"
    assert ack["acknowledged_at"] is not None


def test_list_alerts_acknowledged_filter(engine, alert):
    engine.acknowledge_alert("org1", alert["alert_id"], "alice")
    result = engine.list_alerts("org1", acknowledged=True)
    assert len(result) == 1
    assert result[0]["status"] == "acknowledged"


def test_acknowledge_nonexistent_alert_raises(engine):
    with pytest.raises(ValueError):
        engine.acknowledge_alert("org1", "nonexistent-id", "alice")


# ===========================================================================
# 5. Resolve Alert
# ===========================================================================

def test_resolve_open_alert(engine, alert):
    resolved = engine.resolve_alert("org1", alert["alert_id"], "bob", "Restarted service")
    assert resolved["status"] == "resolved"
    assert resolved["resolved_by"] == "bob"
    assert resolved["resolution"] == "Restarted service"
    assert resolved["resolved_at"] is not None


def test_resolve_acknowledged_alert(engine, alert):
    engine.acknowledge_alert("org1", alert["alert_id"], "alice")
    resolved = engine.resolve_alert("org1", alert["alert_id"], "bob", "Fixed")
    assert resolved["status"] == "resolved"


def test_resolve_nonexistent_alert_raises(engine):
    with pytest.raises(ValueError):
        engine.resolve_alert("org1", "bad-id", "bob", "n/a")


# ===========================================================================
# 6. Alert History
# ===========================================================================

def test_get_alert_history_default_24h(engine, alert):
    history = engine.get_alert_history("org1")
    assert len(history) == 1
    assert history[0]["alert_id"] == alert["alert_id"]


def test_get_alert_history_filter_policy(engine, policy, alert):
    engine.trigger_alert("org1", {"title": "Unrelated", "message": "m"})
    history = engine.get_alert_history("org1", policy_id=policy["policy_id"])
    assert all(a["policy_id"] == policy["policy_id"] for a in history)


def test_get_alert_history_org_isolation(engine, alert):
    assert engine.get_alert_history("org2") == []


# ===========================================================================
# 7. Alerting Stats
# ===========================================================================

def test_get_alerting_stats_empty(engine):
    stats = engine.get_alerting_stats("org1")
    assert stats["policies"] == 0
    assert stats["alerts_24h"] == 0
    assert stats["unacknowledged"] == 0
    assert stats["by_severity"] == {}
    assert stats["mttr_hours"] is None


def test_get_alerting_stats_with_data(engine, policy, alert):
    stats = engine.get_alerting_stats("org1")
    assert stats["policies"] == 1
    assert stats["alerts_24h"] == 1
    assert stats["unacknowledged"] == 1
    assert "high" in stats["by_severity"]


def test_get_alerting_stats_mttr_after_resolve(engine, alert):
    engine.resolve_alert("org1", alert["alert_id"], "bob", "Fixed")
    stats = engine.get_alerting_stats("org1")
    assert stats["mttr_hours"] is not None
    assert stats["mttr_hours"] >= 0


def test_get_alerting_stats_unacknowledged_count(engine):
    engine.trigger_alert("org1", {"title": "A1", "message": "m"})
    a2 = engine.trigger_alert("org1", {"title": "A2", "message": "m"})
    engine.acknowledge_alert("org1", a2["alert_id"], "alice")
    stats = engine.get_alerting_stats("org1")
    assert stats["unacknowledged"] == 1


def test_get_alerting_stats_org_isolation(engine, alert):
    stats = engine.get_alerting_stats("org2")
    assert stats["policies"] == 0
    assert stats["alerts_24h"] == 0
