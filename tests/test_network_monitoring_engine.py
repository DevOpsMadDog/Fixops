"""Tests for NetworkMonitoringEngine — 30+ tests covering interfaces,
traffic samples, alert rules, alerts, stats, and org isolation."""

from __future__ import annotations

import os
import pytest

from core.network_monitoring_engine import NetworkMonitoringEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_nm.db")
    return NetworkMonitoringEngine(db_path=db)


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------


def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "nm.db")
    NetworkMonitoringEngine(db_path=db)
    assert os.path.exists(db)


def test_engine_two_instances_same_db(tmp_path):
    db = str(tmp_path / "nm.db")
    e1 = NetworkMonitoringEngine(db_path=db)
    e2 = NetworkMonitoringEngine(db_path=db)
    e1.register_interface(ORG_A, {"name": "eth0", "if_type": "lan"})
    assert len(e2.list_interfaces(ORG_A)) == 1


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


def test_register_interface_returns_dict(engine):
    result = engine.register_interface(ORG_A, {"name": "eth0", "ip": "10.0.0.1", "if_type": "lan"})
    assert "interface_id" in result
    assert result["org_id"] == ORG_A
    assert result["name"] == "eth0"
    assert result["if_type"] == "lan"
    assert result["ip"] == "10.0.0.1"


def test_register_interface_wan_type(engine):
    result = engine.register_interface(ORG_A, {"name": "eth1", "if_type": "wan"})
    assert result["if_type"] == "wan"


def test_register_interface_dmz_type(engine):
    result = engine.register_interface(ORG_A, {"name": "dmz0", "if_type": "dmz"})
    assert result["if_type"] == "dmz"


def test_register_interface_description(engine):
    result = engine.register_interface(ORG_A, {"name": "eth0", "description": "Primary LAN"})
    assert result["description"] == "Primary LAN"


def test_list_interfaces_empty(engine):
    assert engine.list_interfaces(ORG_A) == []


def test_list_interfaces_returns_all(engine):
    engine.register_interface(ORG_A, {"name": "eth0", "if_type": "lan"})
    engine.register_interface(ORG_A, {"name": "eth1", "if_type": "wan"})
    result = engine.list_interfaces(ORG_A)
    assert len(result) == 2


def test_list_interfaces_filter_by_type(engine):
    engine.register_interface(ORG_A, {"name": "eth0", "if_type": "lan"})
    engine.register_interface(ORG_A, {"name": "eth1", "if_type": "wan"})
    engine.register_interface(ORG_A, {"name": "dmz0", "if_type": "dmz"})
    lans = engine.list_interfaces(ORG_A, if_type="lan")
    assert len(lans) == 1
    assert lans[0]["name"] == "eth0"


def test_list_interfaces_org_isolation(engine):
    engine.register_interface(ORG_A, {"name": "eth0"})
    engine.register_interface(ORG_B, {"name": "eth1"})
    assert len(engine.list_interfaces(ORG_A)) == 1
    assert len(engine.list_interfaces(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Traffic samples
# ---------------------------------------------------------------------------


def test_record_traffic_sample_returns_dict(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    sample = engine.record_traffic_sample(
        ORG_A, iface["interface_id"],
        {"bytes_in": 1000, "bytes_out": 2000, "packets_in": 10, "packets_out": 20},
    )
    assert "sample_id" in sample
    assert sample["bytes_in"] == 1000
    assert sample["bytes_out"] == 2000
    assert sample["packets_in"] == 10
    assert sample["packets_out"] == 20
    assert sample["interface_id"] == iface["interface_id"]


def test_record_traffic_sample_custom_timestamp(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    ts = "2025-01-01T00:00:00+00:00"
    sample = engine.record_traffic_sample(ORG_A, iface["interface_id"], {"timestamp": ts})
    assert sample["sampled_at"] == ts


def test_record_multiple_samples(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    for i in range(5):
        engine.record_traffic_sample(ORG_A, iface["interface_id"], {"bytes_in": i * 100})
    stats = engine.get_traffic_stats(ORG_A, iface["interface_id"])
    assert stats["sample_count"] == 5


def test_get_traffic_stats_returns_dict(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    engine.record_traffic_sample(ORG_A, iface["interface_id"], {"bytes_in": 1000, "bytes_out": 2000})
    stats = engine.get_traffic_stats(ORG_A, iface["interface_id"])
    assert "avg_bps" in stats
    assert "peak_bps" in stats
    assert "total_bytes" in stats
    assert stats["total_bytes"] == 3000


def test_get_traffic_stats_empty(engine):
    stats = engine.get_traffic_stats(ORG_A, "nonexistent-iface")
    assert stats["sample_count"] == 0
    assert stats["total_bytes"] == 0
    assert stats["avg_bps"] == 0.0


def test_get_traffic_stats_hours_param(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    engine.record_traffic_sample(ORG_A, iface["interface_id"], {"bytes_in": 500, "bytes_out": 500})
    stats = engine.get_traffic_stats(ORG_A, iface["interface_id"], hours=1)
    assert stats["hours"] == 1


# ---------------------------------------------------------------------------
# Alert rules
# ---------------------------------------------------------------------------


def test_create_alert_rule_returns_dict(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    rule = engine.create_alert_rule(ORG_A, {
        "interface_id": iface["interface_id"],
        "metric": "bytes_in",
        "threshold": 1_000_000,
        "severity": "high",
    })
    assert "rule_id" in rule
    assert rule["metric"] == "bytes_in"
    assert rule["threshold"] == 1_000_000
    assert rule["severity"] == "high"
    assert rule["interface_id"] == iface["interface_id"]


def test_list_alert_rules_empty(engine):
    assert engine.list_alert_rules(ORG_A) == []


def test_list_alert_rules_returns_all(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    engine.create_alert_rule(ORG_A, {"interface_id": iface["interface_id"], "metric": "bytes_in", "threshold": 100})
    engine.create_alert_rule(ORG_A, {"interface_id": iface["interface_id"], "metric": "bytes_out", "threshold": 200})
    assert len(engine.list_alert_rules(ORG_A)) == 2


def test_alert_rules_org_isolation(engine):
    iface_a = engine.register_interface(ORG_A, {"name": "eth0"})
    iface_b = engine.register_interface(ORG_B, {"name": "eth0"})
    engine.create_alert_rule(ORG_A, {"interface_id": iface_a["interface_id"], "threshold": 100})
    engine.create_alert_rule(ORG_B, {"interface_id": iface_b["interface_id"], "threshold": 200})
    assert len(engine.list_alert_rules(ORG_A)) == 1
    assert len(engine.list_alert_rules(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def test_trigger_alert_returns_dict(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    rule = engine.create_alert_rule(ORG_A, {
        "interface_id": iface["interface_id"],
        "metric": "bytes_in",
        "threshold": 1000,
        "severity": "medium",
    })
    alert = engine.trigger_alert(ORG_A, rule["rule_id"], 5000.0)
    assert "alert_id" in alert
    assert alert["rule_id"] == rule["rule_id"]
    assert alert["value"] == 5000.0
    assert alert["severity"] == "medium"


def test_trigger_alert_unknown_rule(engine):
    alert = engine.trigger_alert(ORG_A, "nonexistent-rule", 999.0)
    assert alert["error"] == "rule_not_found"


def test_list_alerts_empty(engine):
    assert engine.list_alerts(ORG_A) == []


def test_list_alerts_returns_triggered(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    rule = engine.create_alert_rule(ORG_A, {"interface_id": iface["interface_id"], "threshold": 0, "severity": "high"})
    engine.trigger_alert(ORG_A, rule["rule_id"], 100.0)
    engine.trigger_alert(ORG_A, rule["rule_id"], 200.0)
    alerts = engine.list_alerts(ORG_A)
    assert len(alerts) == 2


def test_list_alerts_filter_by_severity(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    rule_high = engine.create_alert_rule(ORG_A, {"interface_id": iface["interface_id"], "threshold": 0, "severity": "high"})
    rule_low = engine.create_alert_rule(ORG_A, {"interface_id": iface["interface_id"], "threshold": 0, "severity": "low"})
    engine.trigger_alert(ORG_A, rule_high["rule_id"], 1.0)
    engine.trigger_alert(ORG_A, rule_low["rule_id"], 1.0)
    high_alerts = engine.list_alerts(ORG_A, severity="high")
    assert len(high_alerts) == 1
    assert high_alerts[0]["severity"] == "high"


def test_list_alerts_limit(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    rule = engine.create_alert_rule(ORG_A, {"interface_id": iface["interface_id"], "threshold": 0})
    for _ in range(10):
        engine.trigger_alert(ORG_A, rule["rule_id"], 1.0)
    assert len(engine.list_alerts(ORG_A, limit=5)) == 5


def test_alerts_org_isolation(engine):
    iface_a = engine.register_interface(ORG_A, {"name": "eth0"})
    iface_b = engine.register_interface(ORG_B, {"name": "eth0"})
    rule_a = engine.create_alert_rule(ORG_A, {"interface_id": iface_a["interface_id"], "threshold": 0})
    rule_b = engine.create_alert_rule(ORG_B, {"interface_id": iface_b["interface_id"], "threshold": 0})
    engine.trigger_alert(ORG_A, rule_a["rule_id"], 1.0)
    engine.trigger_alert(ORG_B, rule_b["rule_id"], 1.0)
    assert len(engine.list_alerts(ORG_A)) == 1
    assert len(engine.list_alerts(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_monitoring_stats_empty(engine):
    stats = engine.get_monitoring_stats(ORG_A)
    assert stats["interface_count"] == 0
    assert stats["sample_count"] == 0
    assert stats["alert_count"] == 0
    assert stats["rule_count"] == 0
    assert stats["critical_alerts"] == 0


def test_get_monitoring_stats_counts(engine):
    iface = engine.register_interface(ORG_A, {"name": "eth0"})
    engine.record_traffic_sample(ORG_A, iface["interface_id"], {"bytes_in": 100})
    rule = engine.create_alert_rule(ORG_A, {"interface_id": iface["interface_id"], "threshold": 0, "severity": "critical"})
    engine.trigger_alert(ORG_A, rule["rule_id"], 999.0)
    stats = engine.get_monitoring_stats(ORG_A)
    assert stats["interface_count"] == 1
    assert stats["sample_count"] == 1
    assert stats["rule_count"] == 1
    assert stats["alert_count"] == 1
    assert stats["critical_alerts"] == 1


def test_get_monitoring_stats_org_isolation(engine):
    engine.register_interface(ORG_A, {"name": "eth0"})
    engine.register_interface(ORG_B, {"name": "eth0"})
    engine.register_interface(ORG_B, {"name": "eth1"})
    assert engine.get_monitoring_stats(ORG_A)["interface_count"] == 1
    assert engine.get_monitoring_stats(ORG_B)["interface_count"] == 2
