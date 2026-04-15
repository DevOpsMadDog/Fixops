"""Tests for NetworkAnomalyEngine — 38+ tests covering:
baseline AVG/stdev computation, deviation_pct formula,
50%/100%/200% severity thresholds, anomaly INSERT only when >50%,
spike vs drop detection, org isolation."""

from __future__ import annotations

import os
import pytest

from core.network_anomaly_engine import NetworkAnomalyEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"

SEG = "core-lan"
PROTO = "TCP"
DIR = "inbound"


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_na.db")
    return NetworkAnomalyEngine(db_path=db)


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------


def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "na.db")
    NetworkAnomalyEngine(db_path=db)
    assert os.path.exists(db)


def test_engine_two_instances_same_db(tmp_path):
    db = str(tmp_path / "na.db")
    e1 = NetworkAnomalyEngine(db_path=db)
    e2 = NetworkAnomalyEngine(db_path=db)
    e1.record_sample(ORG_A, SEG, PROTO, DIR, 1000.0, 50.0)
    e2.update_baseline(ORG_A, SEG, PROTO, DIR)
    health = e2.get_baseline_health(ORG_A)
    assert len(health) == 1


# ---------------------------------------------------------------------------
# record_sample
# ---------------------------------------------------------------------------


def test_record_sample_returns_dict(engine):
    s = engine.record_sample(ORG_A, SEG, PROTO, DIR, 1000.0, 50.0)
    assert s["id"]
    assert s["org_id"] == ORG_A
    assert s["segment"] == SEG
    assert s["protocol"] == PROTO
    assert s["direction"] == DIR
    assert s["bytes_per_min"] == 1000.0
    assert s["packets_per_min"] == 50.0
    assert "sampled_at" in s


def test_record_sample_zero_values(engine):
    s = engine.record_sample(ORG_A, SEG, "UDP", "outbound", 0.0, 0.0)
    assert s["bytes_per_min"] == 0.0


def test_record_multiple_samples(engine):
    for i in range(5):
        engine.record_sample(ORG_A, SEG, PROTO, DIR, float(i * 100), float(i * 10))
    trend = engine.get_traffic_trend(ORG_A, SEG, PROTO, hours=24)
    assert len(trend) == 5


# ---------------------------------------------------------------------------
# update_baseline — AVG and stdev computation
# ---------------------------------------------------------------------------


def test_update_baseline_no_samples_returns_zero_count(engine):
    result = engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    assert result["sample_count"] == 0


def test_update_baseline_single_sample_avg(engine):
    engine.record_sample(ORG_A, SEG, PROTO, DIR, 1000.0, 50.0)
    b = engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    assert abs(b["avg_bytes_per_min"] - 1000.0) < 0.01
    assert abs(b["avg_packets_per_min"] - 50.0) < 0.01
    assert b["sample_count"] == 1


def test_update_baseline_multiple_samples_avg(engine):
    for val in [100.0, 200.0, 300.0]:
        engine.record_sample(ORG_A, SEG, PROTO, DIR, val, val / 10)
    b = engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    assert abs(b["avg_bytes_per_min"] - 200.0) < 0.01
    assert b["sample_count"] == 3


def test_update_baseline_stdev_computed(engine):
    for val in [100.0, 200.0, 300.0]:
        engine.record_sample(ORG_A, SEG, PROTO, DIR, val, 10.0)
    b = engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    # stdev([100,200,300]) = 100
    assert abs(b["std_dev_bytes"] - 100.0) < 0.01


def test_update_baseline_stdev_zero_for_single(engine):
    engine.record_sample(ORG_A, SEG, PROTO, DIR, 1000.0, 50.0)
    b = engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    assert b["std_dev_bytes"] == 0.0


def test_update_baseline_is_idempotent(engine):
    for val in [100.0, 200.0]:
        engine.record_sample(ORG_A, SEG, PROTO, DIR, val, 10.0)
    b1 = engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    b2 = engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    assert b1["id"] == b2["id"]
    assert abs(b2["avg_bytes_per_min"] - 150.0) < 0.01


def test_update_baseline_separate_per_protocol(engine):
    engine.record_sample(ORG_A, SEG, "TCP", DIR, 1000.0, 50.0)
    engine.record_sample(ORG_A, SEG, "UDP", DIR, 500.0, 25.0)
    engine.update_baseline(ORG_A, SEG, "TCP", DIR)
    engine.update_baseline(ORG_A, SEG, "UDP", DIR)
    health = engine.get_baseline_health(ORG_A)
    assert len(health) == 2


# ---------------------------------------------------------------------------
# detect_anomalies — no baseline returns empty
# ---------------------------------------------------------------------------


def test_detect_no_baseline_returns_empty(engine):
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 9999.0, 100.0)
    assert result == []


# ---------------------------------------------------------------------------
# detect_anomalies — deviation thresholds
# ---------------------------------------------------------------------------


def _setup_baseline(engine, org, seg, proto, direction, avg_bytes):
    """Record samples so baseline avg = avg_bytes."""
    engine.record_sample(org, seg, proto, direction, avg_bytes, 10.0)
    engine.update_baseline(org, seg, proto, direction)


def test_detect_no_anomaly_within_50pct(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    # 1400 = 40% above 1000 — within threshold
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 1400.0, 50.0)
    assert result == []


def test_detect_no_anomaly_exactly_50pct(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    # exactly 50% — threshold is >50, so not inserted
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 1500.0, 50.0)
    assert result == []


def test_detect_anomaly_just_above_50pct(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    # 1510 = 51% above 1000 — should trigger medium
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 1510.0, 50.0)
    assert len(result) == 1
    assert result[0]["severity"] == "medium"


def test_detect_anomaly_medium_spike(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    # 1600 = 60% above → medium
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 1600.0, 50.0)
    assert result[0]["severity"] == "medium"


def test_detect_anomaly_high_at_100pct(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    # 2010 = >100% above → high
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 2010.0, 50.0)
    assert result[0]["severity"] == "high"


def test_detect_anomaly_critical_at_200pct(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    # 3010 = >200% above → critical
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 3010.0, 50.0)
    assert result[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# detect_anomalies — spike vs drop
# ---------------------------------------------------------------------------


def test_detect_spike_type(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 2500.0, 50.0)
    assert result[0]["anomaly_type"] == "spike"


def test_detect_drop_type(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    # 400 = 60% below → drop
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 400.0, 50.0)
    assert len(result) == 1
    assert result[0]["anomaly_type"] == "drop"


def test_detect_anomaly_returns_deviation_pct(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 2000.0, 50.0)
    # deviation = (2000 - 1000) / 1000 * 100 = 100%
    assert abs(result[0]["deviation_pct"] - 100.0) < 0.01


def test_detect_anomaly_baseline_value_in_result(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 2000.0, 50.0)
    assert result[0]["baseline_value"] == 1000.0
    assert result[0]["observed_value"] == 2000.0


def test_detect_anomaly_status_active(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    result = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 2500.0, 50.0)
    assert result[0]["status"] == "active"


# ---------------------------------------------------------------------------
# resolve_anomaly
# ---------------------------------------------------------------------------


def test_resolve_anomaly(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    anomalies = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 2500.0, 50.0)
    anomaly_id = anomalies[0]["id"]
    result = engine.resolve_anomaly(anomaly_id, ORG_A)
    assert result["status"] == "resolved"
    assert result["resolved_at"] is not None


def test_resolve_anomaly_wrong_org_raises(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    anomalies = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 2500.0, 50.0)
    with pytest.raises(ValueError):
        engine.resolve_anomaly(anomalies[0]["id"], ORG_B)


def test_resolve_anomaly_not_found_raises(engine):
    with pytest.raises(ValueError):
        engine.resolve_anomaly("nonexistent", ORG_A)


# ---------------------------------------------------------------------------
# get_anomaly_summary
# ---------------------------------------------------------------------------


def test_summary_empty(engine):
    s = engine.get_anomaly_summary(ORG_A)
    assert s["total"] == 0
    assert s["active"] == 0
    assert s["by_severity"] == {}
    assert s["recent_anomalies"] == []


def test_summary_counts(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 3500.0, 50.0)  # critical
    engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 2100.0, 50.0)  # high
    s = engine.get_anomaly_summary(ORG_A)
    assert s["total"] == 2
    assert s["active"] == 2
    assert "critical" in s["by_severity"]
    assert "high" in s["by_severity"]


def test_summary_active_count_after_resolve(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    a = engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 3500.0, 50.0)
    engine.resolve_anomaly(a[0]["id"], ORG_A)
    s = engine.get_anomaly_summary(ORG_A)
    assert s["total"] == 1
    assert s["active"] == 0


def test_summary_by_segment(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    _setup_baseline(engine, ORG_A, "dmz", PROTO, DIR, 500.0)
    engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 3500.0, 50.0)
    engine.detect_anomalies(ORG_A, "dmz", PROTO, DIR, 2000.0, 50.0)
    s = engine.get_anomaly_summary(ORG_A)
    assert SEG in s["by_segment"]
    assert "dmz" in s["by_segment"]


# ---------------------------------------------------------------------------
# get_baseline_health
# ---------------------------------------------------------------------------


def test_baseline_health_empty(engine):
    assert engine.get_baseline_health(ORG_A) == []


def test_baseline_health_returns_baselines(engine):
    engine.record_sample(ORG_A, SEG, PROTO, DIR, 1000.0, 50.0)
    engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    health = engine.get_baseline_health(ORG_A)
    assert len(health) == 1
    assert health[0]["segment"] == SEG
    assert health[0]["sample_count"] == 1


# ---------------------------------------------------------------------------
# get_traffic_trend
# ---------------------------------------------------------------------------


def test_traffic_trend_empty(engine):
    result = engine.get_traffic_trend(ORG_A, SEG, PROTO)
    assert result == []


def test_traffic_trend_returns_samples(engine):
    engine.record_sample(ORG_A, SEG, PROTO, DIR, 1000.0, 50.0)
    engine.record_sample(ORG_A, SEG, PROTO, DIR, 1200.0, 60.0)
    result = engine.get_traffic_trend(ORG_A, SEG, PROTO)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_baselines(engine):
    engine.record_sample(ORG_A, SEG, PROTO, DIR, 1000.0, 50.0)
    engine.update_baseline(ORG_A, SEG, PROTO, DIR)
    assert engine.get_baseline_health(ORG_B) == []


def test_org_isolation_samples(engine):
    engine.record_sample(ORG_A, SEG, PROTO, DIR, 1000.0, 50.0)
    result = engine.get_traffic_trend(ORG_B, SEG, PROTO)
    assert result == []


def test_org_isolation_detect(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    # ORG_B has no baseline, should return empty
    result = engine.detect_anomalies(ORG_B, SEG, PROTO, DIR, 9999.0, 100.0)
    assert result == []


def test_org_isolation_summary(engine):
    _setup_baseline(engine, ORG_A, SEG, PROTO, DIR, 1000.0)
    engine.detect_anomalies(ORG_A, SEG, PROTO, DIR, 3500.0, 50.0)
    s = engine.get_anomaly_summary(ORG_B)
    assert s["total"] == 0
