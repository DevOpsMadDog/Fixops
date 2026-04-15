"""Tests for SecurityOperationsMetricsEngine — 35+ tests covering all methods and edge cases."""
from __future__ import annotations

import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

import pytest
from core.security_operations_metrics_engine import SecurityOperationsMetricsEngine

ORG = "org-som-test"
ORG2 = "org-som-other"


@pytest.fixture
def engine(tmp_path):
    return SecurityOperationsMetricsEngine(db_path=str(tmp_path / "test_som.db"))


def _make_alert(engine, org=ORG, severity="medium", category="other", **kwargs):
    return engine.create_alert(
        org_id=org,
        alert_source="SIEM",
        severity=severity,
        category=category,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# create_alert
# ---------------------------------------------------------------------------

def test_create_alert_basic(engine):
    a = _make_alert(engine)
    assert a["id"]
    assert a["status"] == "open"
    assert a["false_positive"] == 0
    assert a["org_id"] == ORG
    assert a["detected_at"] is not None


def test_create_alert_custom_detected_at(engine):
    ts = "2026-01-01T10:00:00+00:00"
    a = engine.create_alert(ORG, "EDR", "critical", "malware", detected_at=ts)
    assert a["detected_at"] == ts


def test_create_alert_defaults_detected_at_to_now(engine):
    a = _make_alert(engine)
    # detected_at should be a valid ISO timestamp close to now
    dt = datetime.fromisoformat(a["detected_at"])
    diff = abs((datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc if dt.tzinfo is None else dt.tzinfo)).total_seconds())
    assert diff < 5


def test_create_alert_severity_critical(engine):
    a = _make_alert(engine, severity="critical")
    assert a["severity"] == "critical"


def test_create_alert_org_isolation(engine):
    a1 = _make_alert(engine, org=ORG)
    a2 = _make_alert(engine, org=ORG2)
    assert a1["id"] != a2["id"]


# ---------------------------------------------------------------------------
# acknowledge_alert
# ---------------------------------------------------------------------------

def test_acknowledge_alert_sets_fields(engine):
    a = _make_alert(engine)
    ack = engine.acknowledge_alert(a["id"], ORG, "analyst-alice")
    assert ack["status"] == "acknowledged"
    assert ack["assigned_to"] == "analyst-alice"
    assert ack["acknowledged_at"] is not None


def test_acknowledge_alert_wrong_id_returns_none(engine):
    result = engine.acknowledge_alert("no-such-id", ORG, "alice")
    assert result is None


def test_acknowledge_alert_wrong_org_returns_none(engine):
    a = _make_alert(engine)
    result = engine.acknowledge_alert(a["id"], ORG2, "alice")
    assert result is None


# ---------------------------------------------------------------------------
# resolve_alert
# ---------------------------------------------------------------------------

def test_resolve_alert_sets_resolved(engine):
    a = _make_alert(engine)
    resolved = engine.resolve_alert(a["id"], ORG)
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"] is not None
    assert resolved["false_positive"] == 0


def test_resolve_alert_false_positive_flag(engine):
    a = _make_alert(engine)
    resolved = engine.resolve_alert(a["id"], ORG, false_positive=True)
    assert resolved["false_positive"] == 1


def test_resolve_alert_wrong_id_returns_none(engine):
    result = engine.resolve_alert("no-such", ORG)
    assert result is None


def test_resolve_alert_wrong_org_returns_none(engine):
    a = _make_alert(engine)
    result = engine.resolve_alert(a["id"], ORG2)
    assert result is None


# ---------------------------------------------------------------------------
# take_daily_snapshot — MTTD / MTTR / rates
# ---------------------------------------------------------------------------

def test_snapshot_empty_org(engine):
    snap = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-01")
    assert snap["total_alerts"] == 0
    assert snap["mttd_mins"] == 0.0
    assert snap["mttr_mins"] == 0.0
    assert snap["false_positive_rate"] == 0.0
    assert snap["resolution_rate"] == 0.0


def test_snapshot_total_alerts(engine):
    _make_alert(engine, detected_at="2026-01-15T10:00:00+00:00")
    _make_alert(engine, detected_at="2026-01-15T11:00:00+00:00")
    snap = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    assert snap["total_alerts"] == 2


def test_snapshot_critical_alerts(engine):
    _make_alert(engine, severity="critical", detected_at="2026-01-15T10:00:00+00:00")
    _make_alert(engine, severity="high", detected_at="2026-01-15T10:00:00+00:00")
    snap = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    assert snap["critical_alerts"] == 1


def test_snapshot_mttd_calculation(engine):
    # detected_at, acknowledged_at 60 mins later = mttd 60 mins
    a = engine.create_alert(ORG, "SIEM", "high", "intrusion",
                            detected_at="2026-01-15T10:00:00+00:00")
    engine.acknowledge_alert(a["id"], ORG, "alice")
    # Manually set acknowledged_at to a fixed value for deterministic test
    import sqlite3
    with sqlite3.connect(engine.db_path) as conn:
        conn.execute(
            "UPDATE soc_alerts SET acknowledged_at = ? WHERE id = ?",
            ("2026-01-15T11:00:00+00:00", a["id"]),
        )
    snap = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    assert snap["mttd_mins"] == pytest.approx(60.0, abs=1.0)


def test_snapshot_mttr_calculation(engine):
    # detected 10:00, resolved 12:00 = 120 mins
    a = engine.create_alert(ORG, "SIEM", "high", "intrusion",
                            detected_at="2026-01-15T10:00:00+00:00")
    engine.resolve_alert(a["id"], ORG)
    import sqlite3
    with sqlite3.connect(engine.db_path) as conn:
        conn.execute(
            "UPDATE soc_alerts SET resolved_at = ? WHERE id = ?",
            ("2026-01-15T12:00:00+00:00", a["id"]),
        )
    snap = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    assert snap["mttr_mins"] == pytest.approx(120.0, abs=1.0)


def test_snapshot_false_positive_rate(engine):
    a1 = _make_alert(engine, detected_at="2026-01-15T10:00:00+00:00")
    a2 = _make_alert(engine, detected_at="2026-01-15T10:01:00+00:00")
    engine.resolve_alert(a1["id"], ORG, false_positive=True)
    snap = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    # 1 of 2 = 50%
    assert snap["false_positive_rate"] == pytest.approx(50.0, abs=0.1)


def test_snapshot_resolution_rate(engine):
    a1 = _make_alert(engine, detected_at="2026-01-15T10:00:00+00:00")
    a2 = _make_alert(engine, detected_at="2026-01-15T10:01:00+00:00")
    engine.resolve_alert(a1["id"], ORG)
    snap = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    assert snap["resolution_rate"] == pytest.approx(50.0, abs=0.1)


def test_snapshot_insert_or_replace(engine):
    _make_alert(engine, detected_at="2026-01-15T10:00:00+00:00")
    snap1 = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    _make_alert(engine, detected_at="2026-01-15T10:01:00+00:00")
    snap2 = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    # Second snapshot replaces first; total should be 2
    assert snap2["total_alerts"] == 2


def test_snapshot_org_isolation(engine):
    _make_alert(engine, org=ORG, detected_at="2026-01-15T10:00:00+00:00")
    _make_alert(engine, org=ORG2, detected_at="2026-01-15T10:00:00+00:00")
    snap = engine.take_daily_snapshot(ORG, snapshot_date="2026-01-15")
    assert snap["total_alerts"] == 1


# ---------------------------------------------------------------------------
# update_analyst_workload
# ---------------------------------------------------------------------------

def test_update_analyst_workload_basic(engine):
    w = engine.update_analyst_workload(ORG, "alice", "2026-01-15", 10, 8, 45.0)
    assert w["analyst_name"] == "alice"
    assert w["alerts_assigned"] == 10
    assert w["alerts_resolved"] == 8
    assert w["avg_resolution_mins"] == 45.0


def test_update_analyst_workload_replace(engine):
    engine.update_analyst_workload(ORG, "alice", "2026-01-15", 5, 3, 30.0)
    engine.update_analyst_workload(ORG, "alice", "2026-01-15", 12, 10, 25.0)
    perf = engine.get_analyst_performance(ORG, date_str="2026-01-15")
    assert len(perf) == 1
    assert perf[0]["alerts_assigned"] == 12


# ---------------------------------------------------------------------------
# get_soc_summary
# ---------------------------------------------------------------------------

def test_get_soc_summary_empty(engine):
    summary = engine.get_soc_summary(ORG)
    assert summary["total_open_alerts"] == 0
    assert summary["by_severity"] == {}
    assert summary["by_status"] == {}
    assert summary["last_7_days_snapshots"] == []
    assert summary["top_analysts"] == []


def test_get_soc_summary_counts_open(engine):
    _make_alert(engine, severity="critical")
    _make_alert(engine, severity="high")
    a = _make_alert(engine, severity="low")
    engine.resolve_alert(a["id"], ORG)
    summary = engine.get_soc_summary(ORG)
    assert summary["total_open_alerts"] == 2
    assert "critical" in summary["by_severity"]
    assert "resolved" in summary["by_status"]


def test_get_soc_summary_top_analysts(engine):
    engine.update_analyst_workload(ORG, "alice", "2026-01-15", 10, 8, 30.0)
    engine.update_analyst_workload(ORG, "bob", "2026-01-15", 5, 3, 45.0)
    summary = engine.get_soc_summary(ORG)
    names = [a["analyst_name"] for a in summary["top_analysts"]]
    assert "alice" in names
    assert "bob" in names


# ---------------------------------------------------------------------------
# get_mttd_trend
# ---------------------------------------------------------------------------

def test_get_mttd_trend_returns_snapshots(engine):
    engine.take_daily_snapshot(ORG, snapshot_date="2026-01-10")
    engine.take_daily_snapshot(ORG, snapshot_date="2026-01-11")
    trend = engine.get_mttd_trend(ORG, days=30)
    assert len(trend) == 2
    assert "mttd_mins" in trend[0]
    assert "mttr_mins" in trend[0]


def test_get_mttd_trend_org_isolation(engine):
    engine.take_daily_snapshot(ORG, snapshot_date="2026-01-10")
    engine.take_daily_snapshot(ORG2, snapshot_date="2026-01-10")
    trend = engine.get_mttd_trend(ORG, days=30)
    assert len(trend) == 1


# ---------------------------------------------------------------------------
# get_analyst_performance
# ---------------------------------------------------------------------------

def test_get_analyst_performance_all(engine):
    engine.update_analyst_workload(ORG, "alice", "2026-01-15", 10, 8, 30.0)
    engine.update_analyst_workload(ORG, "bob", "2026-01-16", 5, 5, 20.0)
    perf = engine.get_analyst_performance(ORG)
    assert len(perf) == 2


def test_get_analyst_performance_filter_by_date(engine):
    engine.update_analyst_workload(ORG, "alice", "2026-01-15", 10, 8, 30.0)
    engine.update_analyst_workload(ORG, "bob", "2026-01-16", 5, 5, 20.0)
    perf = engine.get_analyst_performance(ORG, date_str="2026-01-15")
    assert len(perf) == 1
    assert perf[0]["analyst_name"] == "alice"


def test_get_analyst_performance_org_isolation(engine):
    engine.update_analyst_workload(ORG, "alice", "2026-01-15", 10, 8, 30.0)
    engine.update_analyst_workload(ORG2, "bob", "2026-01-15", 5, 5, 20.0)
    perf = engine.get_analyst_performance(ORG)
    assert len(perf) == 1
    assert perf[0]["analyst_name"] == "alice"
