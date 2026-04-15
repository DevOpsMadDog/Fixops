"""Tests for NetworkThreatEngine.

Tests cover: threat dedup logic, confidence clamping, rule management,
baseline anomaly detection (exact 25% boundary), stats, and resolve lifecycle.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.network_threat_engine import NetworkThreatEngine


@pytest.fixture
def engine(tmp_path):
    return NetworkThreatEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Threat creation
# ---------------------------------------------------------------------------


def test_record_threat_basic(engine):
    t = engine.record_threat(
        "org1", "C2 Beacon", "c2-communication",
        "10.0.0.1", "192.168.1.1", 443, "https", "high", 0.9
    )
    assert t["id"]
    assert t["org_id"] == "org1"
    assert t["threat_name"] == "C2 Beacon"
    assert t["threat_type"] == "c2-communication"
    assert t["source_ip"] == "10.0.0.1"
    assert t["dest_ip"] == "192.168.1.1"
    assert t["dest_port"] == 443
    assert t["protocol"] == "https"
    assert t["severity"] == "high"
    assert t["confidence"] == pytest.approx(0.9)
    assert t["status"] == "active"
    assert t["packet_count"] == 1


def test_record_threat_dedup_updates_existing(engine):
    """Same org+type+src+dst active threat → update last_seen and packet_count."""
    t1 = engine.record_threat(
        "org1", "Scan1", "port-scan", "10.0.0.2", "10.0.0.3", 22, "tcp", "medium", 0.7
    )
    t2 = engine.record_threat(
        "org1", "Scan2", "port-scan", "10.0.0.2", "10.0.0.3", 22, "tcp", "medium", 0.7
    )
    # Same id returned / same threat updated
    assert t1["id"] == t2["id"]
    assert t2["packet_count"] == 2


def test_record_threat_dedup_different_type_creates_new(engine):
    """Different threat_type → different record."""
    t1 = engine.record_threat(
        "org1", "T1", "port-scan", "10.0.0.1", "10.0.0.2", 80, "tcp", "low", 0.5
    )
    t2 = engine.record_threat(
        "org1", "T2", "ddos", "10.0.0.1", "10.0.0.2", 80, "tcp", "low", 0.5
    )
    assert t1["id"] != t2["id"]


def test_record_threat_dedup_different_org_creates_new(engine):
    t1 = engine.record_threat(
        "org1", "T", "botnet", "1.1.1.1", "2.2.2.2", 6667, "tcp", "critical", 0.8
    )
    t2 = engine.record_threat(
        "org2", "T", "botnet", "1.1.1.1", "2.2.2.2", 6667, "tcp", "critical", 0.8
    )
    assert t1["id"] != t2["id"]


def test_record_threat_dedup_resolved_creates_new(engine):
    """Resolved threat does NOT match dedup — new record created."""
    t1 = engine.record_threat(
        "org1", "T", "lateral-movement", "10.1.1.1", "10.1.1.2", 445, "tcp", "high", 0.6
    )
    engine.resolve_threat(t1["id"], "org1")
    t2 = engine.record_threat(
        "org1", "T", "lateral-movement", "10.1.1.1", "10.1.1.2", 445, "tcp", "high", 0.6
    )
    assert t1["id"] != t2["id"]
    assert t2["status"] == "active"


def test_confidence_clamped_above_one(engine):
    t = engine.record_threat(
        "org1", "T", "exfiltration", "1.1.1.1", "2.2.2.2", 443, "https", "critical", 1.5
    )
    assert t["confidence"] == pytest.approx(1.0)


def test_confidence_clamped_below_zero(engine):
    t = engine.record_threat(
        "org1", "T", "exfiltration", "1.1.1.1", "2.2.2.2", 443, "https", "critical", -0.3
    )
    assert t["confidence"] == pytest.approx(0.0)


def test_confidence_boundary_zero(engine):
    t = engine.record_threat(
        "org1", "T", "dns-tunneling", "1.1.1.1", "2.2.2.2", 53, "dns", "low", 0.0
    )
    assert t["confidence"] == pytest.approx(0.0)


def test_confidence_boundary_one(engine):
    t = engine.record_threat(
        "org1", "T", "mitm", "1.1.1.1", "2.2.2.2", 8080, "http", "high", 1.0
    )
    assert t["confidence"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Resolve
# ---------------------------------------------------------------------------


def test_resolve_threat(engine):
    t = engine.record_threat(
        "org1", "T", "botnet", "5.5.5.5", "6.6.6.6", 80, "tcp", "critical", 0.9
    )
    resolved = engine.resolve_threat(t["id"], "org1")
    assert resolved["status"] == "resolved"


def test_resolve_threat_not_found(engine):
    with pytest.raises(KeyError):
        engine.resolve_threat("nonexistent-id", "org1")


def test_resolve_threat_wrong_org(engine):
    t = engine.record_threat(
        "org1", "T", "botnet", "5.5.5.5", "6.6.6.6", 80, "tcp", "critical", 0.9
    )
    with pytest.raises(KeyError):
        engine.resolve_threat(t["id"], "org2")


# ---------------------------------------------------------------------------
# get_active_threats
# ---------------------------------------------------------------------------


def test_get_active_threats_all(engine):
    engine.record_threat("org1", "T1", "ddos", "1.1.1.1", "2.2.2.2", 80, "tcp", "high", 0.8)
    engine.record_threat("org1", "T2", "botnet", "3.3.3.3", "4.4.4.4", 443, "https", "critical", 0.9)
    threats = engine.get_active_threats("org1")
    assert len(threats) == 2


def test_get_active_threats_filter_type(engine):
    engine.record_threat("org1", "T1", "ddos", "1.1.1.1", "2.2.2.2", 80, "tcp", "high", 0.8)
    engine.record_threat("org1", "T2", "botnet", "3.3.3.3", "4.4.4.4", 443, "https", "critical", 0.9)
    threats = engine.get_active_threats("org1", threat_type="ddos")
    assert len(threats) == 1
    assert threats[0]["threat_type"] == "ddos"


def test_get_active_threats_filter_severity(engine):
    engine.record_threat("org1", "T1", "ddos", "1.1.1.1", "2.2.2.2", 80, "tcp", "high", 0.8)
    engine.record_threat("org1", "T2", "botnet", "3.3.3.3", "4.4.4.4", 443, "https", "critical", 0.9)
    threats = engine.get_active_threats("org1", severity="critical")
    assert len(threats) == 1
    assert threats[0]["severity"] == "critical"


def test_get_active_threats_excludes_resolved(engine):
    t = engine.record_threat("org1", "T", "port-scan", "1.1.1.1", "2.2.2.2", 22, "tcp", "low", 0.3)
    engine.resolve_threat(t["id"], "org1")
    assert engine.get_active_threats("org1") == []


def test_get_active_threats_org_isolation(engine):
    engine.record_threat("org1", "T", "ddos", "1.1.1.1", "2.2.2.2", 80, "tcp", "high", 0.8)
    assert engine.get_active_threats("org2") == []


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_create_rule(engine):
    r = engine.create_rule("org1", "Block C2", "signature", "10.0.0.1/32", "block")
    assert r["id"]
    assert r["rule_name"] == "Block C2"
    assert r["rule_type"] == "signature"
    assert r["pattern"] == "10.0.0.1/32"
    assert r["action"] == "block"
    assert r["enabled"] == 1
    assert r["match_count"] == 0


def test_trigger_rule(engine):
    r = engine.create_rule("org1", "Alert DDoS", "threshold", "pps>1000", "alert")
    triggered = engine.trigger_rule(r["id"], "org1")
    assert triggered["match_count"] == 1
    assert triggered["last_matched"] != ""


def test_trigger_rule_increments_multiple(engine):
    r = engine.create_rule("org1", "R", "behavioral", "pattern", "log")
    engine.trigger_rule(r["id"], "org1")
    engine.trigger_rule(r["id"], "org1")
    r3 = engine.trigger_rule(r["id"], "org1")
    assert r3["match_count"] == 3


def test_trigger_rule_not_found(engine):
    with pytest.raises(KeyError):
        engine.trigger_rule("nonexistent", "org1")


def test_list_rules_all(engine):
    engine.create_rule("org1", "R1", "signature", "p1", "block")
    engine.create_rule("org1", "R2", "anomaly", "p2", "alert")
    rules = engine.list_rules("org1")
    assert len(rules) == 2


def test_list_rules_filter_enabled(engine):
    r = engine.create_rule("org1", "R1", "signature", "p1", "block")
    # Manually disable
    import sqlite3
    conn = sqlite3.connect(engine._db_path)
    conn.execute("UPDATE threat_rules SET enabled=0 WHERE id=?", (r["id"],))
    conn.commit()
    conn.close()

    enabled = engine.list_rules("org1", enabled=True)
    disabled = engine.list_rules("org1", enabled=False)
    assert len(enabled) == 0
    assert len(disabled) == 1


def test_list_rules_org_isolation(engine):
    engine.create_rule("org1", "R", "signature", "p", "block")
    assert engine.list_rules("org2") == []


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


def test_update_baseline_creates(engine):
    b = engine.update_baseline("org1", "packets_per_sec", 1000.0, 1100.0)
    assert b["metric_name"] == "packets_per_sec"
    assert b["baseline_value"] == pytest.approx(1000.0)
    assert b["current_value"] == pytest.approx(1100.0)
    assert b["deviation_pct"] == pytest.approx(10.0)
    assert b["anomaly"] == 0


def test_update_baseline_upsert(engine):
    b1 = engine.update_baseline("org1", "conn_rate", 500.0, 500.0)
    b2 = engine.update_baseline("org1", "conn_rate", 500.0, 700.0)
    assert b1["id"] == b2["id"]
    assert b2["deviation_pct"] == pytest.approx(40.0)
    assert b2["anomaly"] == 1


def test_baseline_anomaly_exactly_25_not_anomaly(engine):
    """Deviation of exactly 25% → anomaly=0 (threshold is >25)."""
    b = engine.update_baseline("org1", "metric_x", 100.0, 125.0)
    assert b["deviation_pct"] == pytest.approx(25.0)
    assert b["anomaly"] == 0


def test_baseline_anomaly_above_25_is_anomaly(engine):
    """Deviation of 25.1% → anomaly=1."""
    b = engine.update_baseline("org1", "metric_y", 1000.0, 1251.0)
    assert b["deviation_pct"] == pytest.approx(25.1)
    assert b["anomaly"] == 1


def test_baseline_below_baseline_is_anomaly(engine):
    """Negative deviation (drop) also triggers anomaly if >25%."""
    b = engine.update_baseline("org1", "metric_z", 200.0, 100.0)
    assert b["deviation_pct"] == pytest.approx(50.0)
    assert b["anomaly"] == 1


def test_get_anomalous_baselines(engine):
    engine.update_baseline("org1", "m1", 100.0, 200.0)   # 100% — anomaly
    engine.update_baseline("org1", "m2", 100.0, 110.0)   # 10%  — normal
    anomalous = engine.get_anomalous_baselines("org1")
    assert len(anomalous) == 1
    assert anomalous[0]["metric_name"] == "m1"


def test_get_anomalous_baselines_org_isolation(engine):
    engine.update_baseline("org1", "m1", 100.0, 200.0)
    assert engine.get_anomalous_baselines("org2") == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_threat_stats_empty(engine):
    stats = engine.get_threat_stats("org1")
    assert stats["total"] == 0
    assert stats["active"] == 0
    assert stats["resolved"] == 0
    assert stats["by_severity"] == {}
    assert stats["by_type"] == {}
    assert stats["top_source_ips"] == []


def test_get_threat_stats_counts(engine):
    engine.record_threat("org1", "T1", "ddos", "1.1.1.1", "2.2.2.2", 80, "tcp", "high", 0.8)
    engine.record_threat("org1", "T2", "botnet", "3.3.3.3", "4.4.4.4", 443, "https", "critical", 0.9)
    t3 = engine.record_threat("org1", "T3", "port-scan", "5.5.5.5", "6.6.6.6", 22, "tcp", "low", 0.3)
    engine.resolve_threat(t3["id"], "org1")

    stats = engine.get_threat_stats("org1")
    assert stats["total"] == 3
    assert stats["active"] == 2
    assert stats["resolved"] == 1
    assert stats["by_severity"].get("high") == 1
    assert stats["by_severity"].get("critical") == 1
    assert stats["by_type"].get("ddos") == 1


def test_get_threat_stats_top_source_ips(engine):
    # Create multiple hits from same source via dedup
    engine.record_threat("org1", "T", "ddos", "8.8.8.8", "9.9.9.9", 80, "tcp", "high", 0.9)
    engine.record_threat("org1", "T", "ddos", "8.8.8.8", "9.9.9.9", 80, "tcp", "high", 0.9)
    engine.record_threat("org1", "T", "ddos", "8.8.8.8", "9.9.9.9", 80, "tcp", "high", 0.9)

    stats = engine.get_threat_stats("org1")
    assert stats["top_source_ips"][0]["source_ip"] == "8.8.8.8"
    assert stats["top_source_ips"][0]["packet_count"] == 3


def test_get_threat_stats_org_isolation(engine):
    engine.record_threat("org1", "T", "ddos", "1.1.1.1", "2.2.2.2", 80, "tcp", "high", 0.8)
    stats = engine.get_threat_stats("org2")
    assert stats["total"] == 0
