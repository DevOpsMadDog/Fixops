"""Tests for NetworkTrafficEngine — 30+ tests covering all methods."""

import pytest
from core.network_traffic_engine import NetworkTrafficEngine


@pytest.fixture
def engine(tmp_path, monkeypatch):
    """Fresh engine pointed at tmp_path."""
    import core.network_traffic_engine as mod
    monkeypatch.setattr(mod, "_DEFAULT_DATA_DIR", tmp_path)
    e = NetworkTrafficEngine()
    return e


ORG = "org-net-test"
ORG2 = "org-net-test-2"


# ---------------------------------------------------------------------------
# record_flow — basic
# ---------------------------------------------------------------------------

def test_record_flow_basic(engine):
    flow = engine.record_flow(ORG, {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "dns"})
    assert flow["id"]
    assert flow["org_id"] == ORG
    assert flow["protocol"] == "dns"
    assert flow["dst_port"] == 53


def test_record_flow_defaults(engine):
    flow = engine.record_flow(ORG, {})
    assert flow["src_ip"] == ""
    assert flow["direction"] == "outbound"
    assert flow["flagged"] == 0
    assert flow["risk_score"] == 0.0


def test_record_flow_invalid_protocol(engine):
    with pytest.raises(ValueError, match="protocol"):
        engine.record_flow(ORG, {"protocol": "ftp_bad"})


def test_record_flow_invalid_direction(engine):
    with pytest.raises(ValueError, match="direction"):
        engine.record_flow(ORG, {"direction": "sideways"})


# ---------------------------------------------------------------------------
# Anomaly detection — C2 traffic
# ---------------------------------------------------------------------------

def test_detect_c2_traffic_port_6667(engine):
    flow = engine.record_flow(ORG, {
        "src_ip": "10.0.0.5", "dst_ip": "evil.com", "dst_port": 6667,
        "direction": "outbound", "bytes_sent": 1000
    })
    assert flow["anomaly_type"] == "c2_traffic"
    assert flow["risk_score"] == pytest.approx(0.85)
    assert flow["flagged"] == 1


def test_detect_c2_traffic_port_31337(engine):
    flow = engine.record_flow(ORG, {
        "dst_port": 31337, "direction": "outbound"
    })
    assert flow["anomaly_type"] == "c2_traffic"


def test_detect_c2_traffic_port_4444(engine):
    flow = engine.record_flow(ORG, {"dst_port": 4444, "direction": "outbound"})
    assert flow["anomaly_type"] == "c2_traffic"


def test_c2_not_flagged_inbound(engine):
    # C2 rule only fires on outbound
    flow = engine.record_flow(ORG, {"dst_port": 6667, "direction": "inbound"})
    assert flow["anomaly_type"] != "c2_traffic"


# ---------------------------------------------------------------------------
# Anomaly detection — data exfiltration
# ---------------------------------------------------------------------------

def test_detect_data_exfil(engine):
    flow = engine.record_flow(ORG, {
        "src_ip": "10.0.0.2", "dst_ip": "storage.example.com",
        "bytes_sent": 200_000_000, "direction": "outbound"
    })
    assert flow["anomaly_type"] == "data_exfil"
    assert flow["risk_score"] == pytest.approx(0.80)
    assert flow["flagged"] == 1


def test_data_exfil_not_flagged_below_threshold(engine):
    flow = engine.record_flow(ORG, {
        "bytes_sent": 50_000_000, "direction": "outbound"
    })
    assert flow["anomaly_type"] != "data_exfil"


# ---------------------------------------------------------------------------
# Anomaly detection — brute force
# ---------------------------------------------------------------------------

def test_detect_brute_force(engine):
    for _ in range(3):
        engine.record_flow(ORG, {
            "src_ip": "192.168.1.50", "dst_port": 22,
            "bytes_received": 50, "direction": "inbound"
        })
    flow = engine.record_flow(ORG, {
        "src_ip": "192.168.1.50", "dst_port": 22,
        "bytes_received": 50, "direction": "inbound"
    })
    assert flow["anomaly_type"] == "brute_force"
    assert flow["risk_score"] == pytest.approx(0.65)


# ---------------------------------------------------------------------------
# Normal flows
# ---------------------------------------------------------------------------

def test_normal_flow_not_flagged(engine):
    flow = engine.record_flow(ORG, {
        "src_ip": "10.0.0.1", "dst_ip": "api.example.com",
        "dst_port": 443, "protocol": "https", "bytes_sent": 5000,
        "direction": "outbound"
    })
    assert flow["flagged"] == 0
    assert flow["anomaly_type"] is None


# ---------------------------------------------------------------------------
# list_flows
# ---------------------------------------------------------------------------

def test_list_flows_all(engine):
    engine.record_flow(ORG, {"src_ip": "10.0.0.1"})
    engine.record_flow(ORG, {"src_ip": "10.0.0.2"})
    flows = engine.list_flows(ORG)
    assert len(flows) >= 2


def test_list_flows_flagged_filter(engine):
    engine.record_flow(ORG, {"dst_port": 6667, "direction": "outbound"})
    engine.record_flow(ORG, {"dst_port": 443, "direction": "outbound"})
    flagged = engine.list_flows(ORG, flagged=True)
    assert all(f["flagged"] == 1 for f in flagged)
    not_flagged = engine.list_flows(ORG, flagged=False)
    assert all(f["flagged"] == 0 for f in not_flagged)


def test_list_flows_anomaly_type_filter(engine):
    engine.record_flow(ORG, {"dst_port": 6667, "direction": "outbound"})
    flows = engine.list_flows(ORG, anomaly_type="c2_traffic")
    assert all(f["anomaly_type"] == "c2_traffic" for f in flows)


def test_list_flows_src_ip_filter(engine):
    engine.record_flow(ORG, {"src_ip": "10.1.1.1"})
    engine.record_flow(ORG, {"src_ip": "10.2.2.2"})
    flows = engine.list_flows(ORG, src_ip="10.1.1.1")
    assert all(f["src_ip"] == "10.1.1.1" for f in flows)


def test_list_flows_limit(engine):
    for i in range(10):
        engine.record_flow(ORG, {"src_ip": f"10.0.0.{i}"})
    flows = engine.list_flows(ORG, limit=5)
    assert len(flows) <= 5


# ---------------------------------------------------------------------------
# get_flow
# ---------------------------------------------------------------------------

def test_get_flow_found(engine):
    flow = engine.record_flow(ORG, {"src_ip": "1.2.3.4"})
    result = engine.get_flow(ORG, flow["id"])
    assert result is not None
    assert result["id"] == flow["id"]


def test_get_flow_not_found(engine):
    assert engine.get_flow(ORG, "nonexistent-id") is None


def test_get_flow_org_isolation(engine):
    flow = engine.record_flow(ORG, {"src_ip": "1.2.3.4"})
    # Different org cannot see this flow
    assert engine.get_flow(ORG2, flow["id"]) is None


# ---------------------------------------------------------------------------
# list_anomalies / resolve_anomaly
# ---------------------------------------------------------------------------

def test_list_anomalies(engine):
    engine.record_flow(ORG, {"dst_port": 6667, "direction": "outbound"})
    anomalies = engine.list_anomalies(ORG)
    assert len(anomalies) >= 1
    assert anomalies[0]["anomaly_type"] == "c2_traffic"


def test_list_anomalies_severity_filter(engine):
    engine.record_flow(ORG, {"dst_port": 6667, "direction": "outbound"})
    critical = engine.list_anomalies(ORG, severity="critical")
    assert all(a["severity"] == "critical" for a in critical)


def test_list_anomalies_status_filter(engine):
    engine.record_flow(ORG, {"dst_port": 6667, "direction": "outbound"})
    new_ones = engine.list_anomalies(ORG, status="new")
    assert all(a["status"] == "new" for a in new_ones)


def test_resolve_anomaly(engine):
    engine.record_flow(ORG, {"dst_port": 6667, "direction": "outbound"})
    anomalies = engine.list_anomalies(ORG, status="new")
    assert len(anomalies) >= 1
    found = engine.resolve_anomaly(ORG, anomalies[0]["id"])
    assert found is True
    resolved = engine.list_anomalies(ORG, status="resolved")
    assert len(resolved) >= 1


def test_resolve_anomaly_not_found(engine):
    assert engine.resolve_anomaly(ORG, "no-such-id") is False


# ---------------------------------------------------------------------------
# Rules CRUD
# ---------------------------------------------------------------------------

def test_create_rule_basic(engine):
    rule = engine.create_rule(ORG, {"rule_name": "Block IRC", "dst_cidr": "0.0.0.0/0", "action": "deny"})
    assert rule["id"]
    assert rule["rule_name"] == "Block IRC"
    assert rule["action"] == "deny"


def test_create_rule_requires_name(engine):
    with pytest.raises(ValueError, match="rule_name"):
        engine.create_rule(ORG, {"rule_name": ""})


def test_create_rule_invalid_action(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_rule(ORG, {"rule_name": "bad", "action": "block_all"})


def test_list_rules(engine):
    engine.create_rule(ORG, {"rule_name": "Rule A", "priority": 10})
    engine.create_rule(ORG, {"rule_name": "Rule B", "priority": 5})
    rules = engine.list_rules(ORG)
    assert len(rules) >= 2
    # Ordered by priority ASC
    priorities = [r["priority"] for r in rules]
    assert priorities == sorted(priorities)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_traffic_stats_empty(engine):
    stats = engine.get_traffic_stats(ORG)
    assert stats["total_flows"] == 0
    assert stats["flagged_flows"] == 0
    assert stats["anomaly_rate"] == 0.0


def test_get_traffic_stats_with_data(engine):
    engine.record_flow(ORG, {"src_ip": "10.0.0.1", "dst_port": 443, "protocol": "https"})
    engine.record_flow(ORG, {"src_ip": "10.0.0.2", "dst_port": 6667, "direction": "outbound"})
    stats = engine.get_traffic_stats(ORG)
    assert stats["total_flows"] >= 2
    assert stats["flagged_flows"] >= 1
    assert "c2_traffic" in stats["by_anomaly_type"]
    assert stats["anomaly_rate"] > 0


def test_get_top_talkers(engine):
    engine.record_flow(ORG, {"src_ip": "10.0.0.1", "bytes_sent": 1000, "bytes_received": 500})
    engine.record_flow(ORG, {"src_ip": "10.0.0.1", "bytes_sent": 2000, "bytes_received": 500})
    engine.record_flow(ORG, {"src_ip": "10.0.0.2", "bytes_sent": 100, "bytes_received": 50})
    talkers = engine.get_top_talkers(ORG, limit=5)
    assert len(talkers) >= 2
    assert talkers[0]["src_ip"] == "10.0.0.1"  # highest total bytes


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_flows(engine):
    engine.record_flow(ORG, {"src_ip": "10.0.0.1"})
    flows_org2 = engine.list_flows(ORG2)
    assert len(flows_org2) == 0


def test_org_isolation_anomalies(engine):
    engine.record_flow(ORG, {"dst_port": 6667, "direction": "outbound"})
    anomalies_org2 = engine.list_anomalies(ORG2)
    assert len(anomalies_org2) == 0


def test_org_isolation_rules(engine):
    engine.create_rule(ORG, {"rule_name": "Org1 Rule"})
    rules_org2 = engine.list_rules(ORG2)
    assert len(rules_org2) == 0


def test_stats_org_isolation(engine):
    engine.record_flow(ORG, {"src_ip": "10.0.0.1"})
    stats = engine.get_traffic_stats(ORG2)
    assert stats["total_flows"] == 0
