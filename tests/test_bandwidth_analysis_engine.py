"""Tests for BandwidthAnalysisEngine — 30+ tests covering link registration,
utilization tracking, anomaly detection, QoS policies, stats, and org isolation."""

from __future__ import annotations

import os
import pytest

from core.bandwidth_analysis_engine import BandwidthAnalysisEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_bw.db")
    return BandwidthAnalysisEngine(db_path=db)


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------


def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "bw.db")
    BandwidthAnalysisEngine(db_path=db)
    assert os.path.exists(db)


def test_engine_two_instances_same_db(tmp_path):
    db = str(tmp_path / "bw.db")
    e1 = BandwidthAnalysisEngine(db_path=db)
    e2 = BandwidthAnalysisEngine(db_path=db)
    e1.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    assert len(e2.list_links(ORG_A)) == 1


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


def test_register_link_returns_dict(engine):
    result = engine.register_link(ORG_A, {"name": "WAN-Primary", "capacity_mbps": 1000, "link_type": "fiber"})
    assert "link_id" in result
    assert result["org_id"] == ORG_A
    assert result["name"] == "WAN-Primary"
    assert result["capacity_mbps"] == 1000.0
    assert result["link_type"] == "fiber"


def test_register_link_vpn_type(engine):
    result = engine.register_link(ORG_A, {"name": "VPN-1", "link_type": "vpn", "capacity_mbps": 50})
    assert result["link_type"] == "vpn"


def test_register_link_mpls_type(engine):
    result = engine.register_link(ORG_A, {"name": "MPLS-1", "link_type": "mpls", "capacity_mbps": 200})
    assert result["link_type"] == "mpls"


def test_register_link_internet_default(engine):
    result = engine.register_link(ORG_A, {"name": "ISP-1"})
    assert result["link_type"] == "internet"


def test_list_links_empty(engine):
    assert engine.list_links(ORG_A) == []


def test_list_links_returns_all(engine):
    engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    engine.register_link(ORG_A, {"name": "WAN-2", "capacity_mbps": 200})
    assert len(engine.list_links(ORG_A)) == 2


def test_list_links_org_isolation(engine):
    engine.register_link(ORG_A, {"name": "WAN-A"})
    engine.register_link(ORG_B, {"name": "WAN-B"})
    assert len(engine.list_links(ORG_A)) == 1
    assert len(engine.list_links(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Utilization
# ---------------------------------------------------------------------------


def test_record_utilization_returns_dict(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    result = engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 45.0, "direction": "inbound"})
    assert "util_id" in result
    assert result["utilization_pct"] == 45.0
    assert result["direction"] == "inbound"
    assert result["link_id"] == link["link_id"]


def test_record_utilization_clamps_to_100(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    result = engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 150.0})
    assert result["utilization_pct"] == 100.0


def test_record_utilization_clamps_to_0(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    result = engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": -10.0})
    assert result["utilization_pct"] == 0.0


def test_record_utilization_custom_timestamp(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    ts = "2025-06-01T12:00:00+00:00"
    result = engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 30.0, "recorded_at": ts})
    assert result["recorded_at"] == ts


def test_get_utilization_trend_returns_dict(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 50.0})
    engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 80.0})
    trend = engine.get_utilization_trend(ORG_A, link["link_id"])
    assert "avg_pct" in trend
    assert "peak_pct" in trend
    assert trend["sample_count"] == 2
    assert trend["peak_pct"] == 80.0
    assert trend["avg_pct"] == 65.0


def test_get_utilization_trend_empty(engine):
    trend = engine.get_utilization_trend(ORG_A, "nonexistent-link")
    assert trend["sample_count"] == 0
    assert trend["avg_pct"] == 0.0
    assert trend["peak_pct"] == 0.0
    assert trend["samples"] == []


def test_get_utilization_trend_samples_list(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    for pct in [10.0, 20.0, 30.0]:
        engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": pct})
    trend = engine.get_utilization_trend(ORG_A, link["link_id"])
    assert len(trend["samples"]) == 3


def test_get_utilization_trend_hours_param(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    trend = engine.get_utilization_trend(ORG_A, link["link_id"], hours=48)
    assert trend["hours"] == 48


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


def test_detect_anomaly_insufficient_data(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    result = engine.detect_anomaly(ORG_A, link["link_id"])
    assert result["anomaly_detected"] is False
    assert "Insufficient" in result["details"]


def test_detect_anomaly_no_anomaly_stable(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    # Record many stable samples then one within range
    for _ in range(20):
        engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 50.0})
    result = engine.detect_anomaly(ORG_A, link["link_id"])
    assert result["anomaly_detected"] is False
    assert result["score"] >= 0.0


def test_detect_anomaly_spike_detected(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    # Baseline: stable at 10%
    for _ in range(20):
        engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 10.0})
    # Spike to 99%
    engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 99.0})
    result = engine.detect_anomaly(ORG_A, link["link_id"])
    assert result["anomaly_detected"] is True
    assert result["score"] > 2.5


def test_detect_anomaly_returns_link_id(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    result = engine.detect_anomaly(ORG_A, link["link_id"])
    assert result["link_id"] == link["link_id"]


def test_detect_anomaly_missing_link(engine):
    result = engine.detect_anomaly(ORG_A, "nonexistent-link")
    assert result["anomaly_detected"] is False


# ---------------------------------------------------------------------------
# QoS policies
# ---------------------------------------------------------------------------


def test_create_qos_policy_returns_dict(engine):
    result = engine.create_qos_policy(ORG_A, {
        "name": "VoIP Priority",
        "priority": 1,
        "traffic_class": "voice",
        "bandwidth_limit_pct": 20.0,
    })
    assert "policy_id" in result
    assert result["name"] == "VoIP Priority"
    assert result["priority"] == 1
    assert result["traffic_class"] == "voice"
    assert result["bandwidth_limit_pct"] == 20.0


def test_create_qos_policy_priority_clamp_low(engine):
    result = engine.create_qos_policy(ORG_A, {"name": "P0", "priority": -5})
    assert result["priority"] == 1


def test_create_qos_policy_priority_clamp_high(engine):
    result = engine.create_qos_policy(ORG_A, {"name": "P9", "priority": 99})
    assert result["priority"] == 8


def test_create_qos_policy_bandwidth_clamp(engine):
    result = engine.create_qos_policy(ORG_A, {"name": "Over", "bandwidth_limit_pct": 200.0})
    assert result["bandwidth_limit_pct"] == 100.0


def test_list_qos_policies_empty(engine):
    assert engine.list_qos_policies(ORG_A) == []


def test_list_qos_policies_ordered_by_priority(engine):
    engine.create_qos_policy(ORG_A, {"name": "Bulk", "priority": 8})
    engine.create_qos_policy(ORG_A, {"name": "Voice", "priority": 1})
    engine.create_qos_policy(ORG_A, {"name": "Video", "priority": 3})
    policies = engine.list_qos_policies(ORG_A)
    priorities = [p["priority"] for p in policies]
    assert priorities == sorted(priorities)


def test_qos_policies_org_isolation(engine):
    engine.create_qos_policy(ORG_A, {"name": "P-A", "priority": 1})
    engine.create_qos_policy(ORG_B, {"name": "P-B", "priority": 2})
    engine.create_qos_policy(ORG_B, {"name": "P-B2", "priority": 3})
    assert len(engine.list_qos_policies(ORG_A)) == 1
    assert len(engine.list_qos_policies(ORG_B)) == 2


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_bandwidth_stats_empty(engine):
    stats = engine.get_bandwidth_stats(ORG_A)
    assert stats["total_links"] == 0
    assert stats["avg_utilization_pct"] == 0.0
    assert stats["high_util_links"] == 0
    assert stats["qos_policy_count"] == 0


def test_get_bandwidth_stats_counts(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 90.0})
    engine.create_qos_policy(ORG_A, {"name": "P1", "priority": 1})
    stats = engine.get_bandwidth_stats(ORG_A)
    assert stats["total_links"] == 1
    assert stats["avg_utilization_pct"] == 90.0
    assert stats["high_util_links"] == 1
    assert stats["qos_policy_count"] == 1


def test_get_bandwidth_stats_low_util_not_counted(engine):
    link = engine.register_link(ORG_A, {"name": "WAN-1", "capacity_mbps": 100})
    engine.record_utilization(ORG_A, link["link_id"], {"utilization_pct": 30.0})
    stats = engine.get_bandwidth_stats(ORG_A)
    assert stats["high_util_links"] == 0


def test_get_bandwidth_stats_org_isolation(engine):
    link_a = engine.register_link(ORG_A, {"name": "WAN-A"})
    link_b1 = engine.register_link(ORG_B, {"name": "WAN-B1"})
    link_b2 = engine.register_link(ORG_B, {"name": "WAN-B2"})
    engine.record_utilization(ORG_A, link_a["link_id"], {"utilization_pct": 50.0})
    engine.record_utilization(ORG_B, link_b1["link_id"], {"utilization_pct": 90.0})
    engine.record_utilization(ORG_B, link_b2["link_id"], {"utilization_pct": 85.0})
    stats_a = engine.get_bandwidth_stats(ORG_A)
    stats_b = engine.get_bandwidth_stats(ORG_B)
    assert stats_a["total_links"] == 1
    assert stats_b["total_links"] == 2
    assert stats_b["high_util_links"] == 2
