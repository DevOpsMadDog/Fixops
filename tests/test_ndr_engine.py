"""Tests for NDREngine — Network Detection & Response Engine.

25+ tests covering org isolation, flow ingestion, risk scoring, auto-alerting,
baselines, segments, anomaly detection, and stats.
"""

from __future__ import annotations

import tempfile
import os
import pytest

from core.ndr_engine import NDREngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_ndr.db")
    return NDREngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# Schema / init
# ---------------------------------------------------------------------------


def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "ndr.db")
    e = NDREngine(db_path=db)
    assert os.path.exists(db)


# ---------------------------------------------------------------------------
# Flow ingestion
# ---------------------------------------------------------------------------


def test_ingest_flow_returns_dict(engine):
    result = engine.ingest_flow(ORG_A, {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "protocol": "TCP"})
    assert "flow_id" in result
    assert result["org_id"] == ORG_A
    assert "risk_score" in result


def test_ingest_flow_stores_fields(engine):
    data = {
        "src_ip": "192.168.1.5",
        "dst_ip": "203.0.113.10",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "HTTPS",
        "bytes_sent": 5000,
        "bytes_recv": 10000,
        "duration_ms": 250,
        "flow_type": "external",
    }
    result = engine.ingest_flow(ORG_A, data)
    assert result["src_ip"] == "192.168.1.5"
    assert result["dst_port"] == 443
    assert result["flow_type"] == "external"
    assert result["bytes_sent"] == 5000


def test_ingest_flow_risk_score_high_risk_port(engine):
    # dst_port 22 (SSH) → +0.3 risk
    result = engine.ingest_flow(ORG_A, {"dst_port": 22, "protocol": "TCP", "flow_type": "internal"})
    assert result["risk_score"] >= 0.3


def test_ingest_flow_risk_score_large_bytes(engine):
    # bytes_sent > 1MB → +0.2
    result = engine.ingest_flow(ORG_A, {"bytes_sent": 2_000_000, "protocol": "TCP"})
    assert result["risk_score"] >= 0.2


def test_ingest_flow_auto_alert_on_high_risk(engine):
    # dst_port 3389 (+0.3) + bytes_sent > 1MB (+0.2) + unusual protocol (+0.2) = 0.7 → alert
    result = engine.ingest_flow(ORG_A, {
        "dst_port": 3389, "bytes_sent": 2_000_000, "protocol": "DNS",
        "flow_type": "external",  # +0.1
    })
    assert result["risk_score"] > 0.7
    assert result["alert_created"] is True


def test_ingest_flow_no_alert_low_risk(engine):
    result = engine.ingest_flow(ORG_A, {"dst_port": 80, "protocol": "HTTP", "bytes_sent": 100})
    assert result["alert_created"] is False


def test_ingest_flow_risk_capped_at_1(engine):
    result = engine.ingest_flow(ORG_A, {
        "dst_port": 22, "bytes_sent": 5_000_000, "protocol": "DNS",
        "flow_type": "external",
    })
    assert result["risk_score"] <= 1.0


def test_ingest_flow_org_isolation(engine):
    engine.ingest_flow(ORG_A, {"src_ip": "10.0.0.1"})
    engine.ingest_flow(ORG_B, {"src_ip": "10.0.0.2"})
    flows_a = engine.list_flows(ORG_A)
    flows_b = engine.list_flows(ORG_B)
    assert all(f["org_id"] == ORG_A for f in flows_a)
    assert all(f["org_id"] == ORG_B for f in flows_b)
    assert len(flows_a) == 1
    assert len(flows_b) == 1


# ---------------------------------------------------------------------------
# List flows
# ---------------------------------------------------------------------------


def test_list_flows_filter_flow_type(engine):
    engine.ingest_flow(ORG_A, {"flow_type": "internal"})
    engine.ingest_flow(ORG_A, {"flow_type": "external"})
    internals = engine.list_flows(ORG_A, flow_type="internal")
    assert all(f["flow_type"] == "internal" for f in internals)


def test_list_flows_filter_min_risk(engine):
    engine.ingest_flow(ORG_A, {"dst_port": 22, "bytes_sent": 2_000_000, "protocol": "DNS", "flow_type": "external"})
    engine.ingest_flow(ORG_A, {"dst_port": 80, "bytes_sent": 100, "protocol": "HTTP"})
    high_risk = engine.list_flows(ORG_A, min_risk=0.6)
    assert len(high_risk) >= 1
    assert all(f["risk_score"] >= 0.6 for f in high_risk)


def test_list_flows_limit(engine):
    for i in range(10):
        engine.ingest_flow(ORG_A, {"src_ip": f"10.0.0.{i}"})
    result = engine.list_flows(ORG_A, limit=3)
    assert len(result) <= 3


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def test_list_alerts_returns_auto_created(engine):
    engine.ingest_flow(ORG_A, {
        "dst_port": 3389, "bytes_sent": 2_000_000, "protocol": "DNS", "flow_type": "external",
    })
    alerts = engine.list_alerts(ORG_A)
    assert len(alerts) >= 1


def test_list_alerts_org_isolation(engine):
    engine.ingest_flow(ORG_A, {
        "dst_port": 22, "bytes_sent": 2_000_000, "protocol": "DNS", "flow_type": "external",
    })
    alerts_b = engine.list_alerts(ORG_B)
    assert len(alerts_b) == 0


def test_update_alert_status(engine):
    engine.ingest_flow(ORG_A, {
        "dst_port": 3389, "bytes_sent": 2_000_000, "protocol": "DNS", "flow_type": "external",
    })
    alerts = engine.list_alerts(ORG_A)
    alert_id = alerts[0]["alert_id"]
    ok = engine.update_alert_status(ORG_A, alert_id, "resolved")
    assert ok is True
    updated = engine.list_alerts(ORG_A, status="resolved")
    assert any(a["alert_id"] == alert_id for a in updated)


def test_update_alert_status_invalid_raises(engine):
    with pytest.raises(ValueError, match="Invalid alert status"):
        engine.update_alert_status(ORG_A, "fake-id", "snoozed")


def test_update_alert_status_wrong_org(engine):
    engine.ingest_flow(ORG_A, {
        "dst_port": 3389, "bytes_sent": 2_000_000, "protocol": "DNS", "flow_type": "external",
    })
    alerts = engine.list_alerts(ORG_A)
    alert_id = alerts[0]["alert_id"]
    ok = engine.update_alert_status(ORG_B, alert_id, "resolved")
    assert ok is False


def test_list_alerts_filter_severity(engine):
    engine.ingest_flow(ORG_A, {
        "dst_port": 3389, "bytes_sent": 2_000_000, "protocol": "DNS", "flow_type": "external",
    })
    critical = engine.list_alerts(ORG_A, severity="critical")
    high = engine.list_alerts(ORG_A, severity="high")
    # At least one of them should have a result (depends on risk score)
    total = len(critical) + len(high)
    assert total >= 1


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


def test_set_and_get_baseline(engine):
    bl = engine.set_baseline(ORG_A, "192.168.1.1", {
        "typical_protocols": ["TCP", "HTTPS"],
        "typical_ports": [443, 80],
        "typical_daily_bytes": 500_000,
        "typical_connections_per_hr": 100,
    })
    assert bl["asset_ip"] == "192.168.1.1"
    assert "baseline_id" in bl

    retrieved = engine.get_baseline(ORG_A, "192.168.1.1")
    assert retrieved is not None
    assert retrieved["typical_daily_bytes"] == 500_000
    assert 443 in retrieved["typical_ports"]


def test_get_baseline_not_found(engine):
    result = engine.get_baseline(ORG_A, "1.2.3.4")
    assert result is None


def test_set_baseline_upsert(engine):
    engine.set_baseline(ORG_A, "10.0.0.1", {"typical_daily_bytes": 1000})
    engine.set_baseline(ORG_A, "10.0.0.1", {"typical_daily_bytes": 2000})
    bl = engine.get_baseline(ORG_A, "10.0.0.1")
    assert bl["typical_daily_bytes"] == 2000


def test_baseline_org_isolation(engine):
    engine.set_baseline(ORG_A, "10.0.0.1", {"typical_daily_bytes": 100})
    assert engine.get_baseline(ORG_B, "10.0.0.1") is None


# ---------------------------------------------------------------------------
# Segments
# ---------------------------------------------------------------------------


def test_add_segment(engine):
    seg = engine.add_segment(ORG_A, {
        "name": "DMZ",
        "cidr": "192.168.100.0/24",
        "segment_type": "dmz",
        "sensitivity": "high",
    })
    assert "segment_id" in seg
    assert seg["name"] == "DMZ"
    assert seg["segment_type"] == "dmz"


def test_list_segments(engine):
    engine.add_segment(ORG_A, {"name": "Internal", "segment_type": "internal"})
    engine.add_segment(ORG_A, {"name": "Cloud", "segment_type": "cloud"})
    segs = engine.list_segments(ORG_A)
    assert len(segs) == 2


def test_list_segments_org_isolation(engine):
    engine.add_segment(ORG_A, {"name": "OT Network", "segment_type": "ot"})
    assert len(engine.list_segments(ORG_B)) == 0


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


def test_detect_anomalies_no_baselines(engine):
    result = engine.detect_anomalies(ORG_A)
    assert result == []


def test_detect_anomalies_excessive_bytes(engine):
    engine.set_baseline(ORG_A, "10.0.0.5", {
        "typical_daily_bytes": 100,
        "typical_ports": [],
    })
    # Ingest a flow with massive bytes_sent (SQLite date filter uses 'now', so set observed_at to now)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    engine.ingest_flow(ORG_A, {
        "src_ip": "10.0.0.5",
        "bytes_sent": 10_000_000,
        "protocol": "TCP",
        "flow_type": "external",
        "observed_at": now,
    })
    anomalies = engine.detect_anomalies(ORG_A)
    types = [a["anomaly_type"] for a in anomalies]
    assert "excessive_bytes" in types


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_ndr_stats_empty(engine):
    stats = engine.get_ndr_stats(ORG_A)
    assert stats["total_flows"] == 0
    assert stats["open_alerts"] == 0
    assert stats["monitored_segments"] == 0


def test_get_ndr_stats_populated(engine):
    engine.ingest_flow(ORG_A, {"flow_type": "external", "protocol": "TCP"})
    engine.ingest_flow(ORG_A, {
        "dst_port": 3389, "bytes_sent": 2_000_000, "protocol": "DNS",
        "flow_type": "exfiltration_suspect",
    })
    engine.add_segment(ORG_A, {"name": "Seg1"})

    stats = engine.get_ndr_stats(ORG_A)
    assert stats["total_flows"] == 2
    assert stats["external_flows"] == 1
    assert stats["exfil_suspects"] == 1
    assert stats["monitored_segments"] == 1


def test_get_ndr_stats_org_isolation(engine):
    engine.ingest_flow(ORG_A, {"flow_type": "external"})
    stats_b = engine.get_ndr_stats(ORG_B)
    assert stats_b["total_flows"] == 0
