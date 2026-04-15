"""Tests for SecurityMetricsCollector — Beast Mode suite."""

from __future__ import annotations

import pytest


@pytest.fixture
def engine(tmp_path):
    from core.security_metrics_collector import SecurityMetricsCollector
    db = str(tmp_path / "test_metrics.db")
    return SecurityMetricsCollector(db_path=db)


ORG = "org-metrics-test"
ORG2 = "org-other"


# ---------------------------------------------------------------------------
# define_metric
# ---------------------------------------------------------------------------

def test_define_metric_basic(engine):
    m = engine.define_metric(ORG, {
        "name": "Open Critical Vulns",
        "category": "vulnerability",
        "unit": "count",
        "target_value": 0.0,
        "critical_threshold": 10.0,
        "warning_threshold": 5.0,
    })
    assert m["metric_id"]
    assert m["name"] == "Open Critical Vulns"
    assert m["category"] == "vulnerability"
    assert m["enabled"] == 1
    assert m["org_id"] == ORG


def test_define_metric_all_categories(engine):
    cats = ["vulnerability", "threat", "compliance", "incident",
            "identity", "endpoint", "cloud", "training"]
    for cat in cats:
        m = engine.define_metric(ORG, {"name": f"Metric {cat}", "category": cat})
        assert m["category"] == cat


def test_define_metric_requires_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.define_metric(ORG, {"category": "threat"})


def test_define_metric_invalid_category(engine):
    with pytest.raises(ValueError, match="category"):
        engine.define_metric(ORG, {"name": "X", "category": "unicorn"})


def test_define_metric_defaults(engine):
    m = engine.define_metric(ORG, {"name": "Simple"})
    assert m["category"] == "vulnerability"
    assert m["enabled"] == 1
    assert m["target_value"] is None
    assert m["critical_threshold"] is None
    assert m["warning_threshold"] is None


# ---------------------------------------------------------------------------
# list_metrics
# ---------------------------------------------------------------------------

def test_list_metrics_org_isolation(engine):
    engine.define_metric(ORG, {"name": "M1"})
    engine.define_metric(ORG2, {"name": "M2"})
    results = engine.list_metrics(ORG)
    assert len(results) == 1
    assert results[0]["name"] == "M1"


def test_list_metrics_filter_by_category(engine):
    engine.define_metric(ORG, {"name": "V1", "category": "vulnerability"})
    engine.define_metric(ORG, {"name": "T1", "category": "threat"})
    vulns = engine.list_metrics(ORG, category="vulnerability")
    assert len(vulns) == 1
    assert vulns[0]["name"] == "V1"


def test_list_metrics_enabled_only_false(engine):
    engine.define_metric(ORG, {"name": "Enabled", "enabled": 1})
    engine.define_metric(ORG, {"name": "Disabled", "enabled": 0})
    all_metrics = engine.list_metrics(ORG, enabled_only=False)
    enabled = engine.list_metrics(ORG, enabled_only=True)
    assert len(all_metrics) == 2
    assert len(enabled) == 1
    assert enabled[0]["name"] == "Enabled"


# ---------------------------------------------------------------------------
# record_reading
# ---------------------------------------------------------------------------

def test_record_reading_normal_status(engine):
    m = engine.define_metric(ORG, {
        "name": "MTTR",
        "critical_threshold": 120.0,
        "warning_threshold": 60.0,
    })
    r = engine.record_reading(ORG, m["metric_id"], 30.0)
    assert r["reading_id"]
    assert r["value"] == 30.0
    assert r["status"] == "normal"
    assert r["source_system"] == "manual"


def test_record_reading_warning_status(engine):
    m = engine.define_metric(ORG, {
        "name": "Alert Rate",
        "critical_threshold": 100.0,
        "warning_threshold": 50.0,
    })
    r = engine.record_reading(ORG, m["metric_id"], 75.0)
    assert r["status"] == "warning"


def test_record_reading_critical_status(engine):
    m = engine.define_metric(ORG, {
        "name": "Breach Count",
        "critical_threshold": 5.0,
        "warning_threshold": 2.0,
    })
    r = engine.record_reading(ORG, m["metric_id"], 10.0)
    assert r["status"] == "critical"


def test_record_reading_creates_critical_alert(engine):
    m = engine.define_metric(ORG, {
        "name": "Phish Rate",
        "critical_threshold": 5.0,
    })
    engine.record_reading(ORG, m["metric_id"], 8.0)
    alerts = engine.list_alerts(ORG, acknowledged=False)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["alert_type"] == "threshold_breach"


def test_record_reading_creates_warning_alert(engine):
    m = engine.define_metric(ORG, {
        "name": "Patch Lag",
        "critical_threshold": 90.0,
        "warning_threshold": 60.0,
    })
    engine.record_reading(ORG, m["metric_id"], 70.0)
    alerts = engine.list_alerts(ORG, acknowledged=False)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"


def test_record_reading_no_alert_when_normal(engine):
    m = engine.define_metric(ORG, {
        "name": "Score",
        "critical_threshold": 90.0,
        "warning_threshold": 60.0,
    })
    engine.record_reading(ORG, m["metric_id"], 10.0)
    alerts = engine.list_alerts(ORG)
    assert len(alerts) == 0


def test_record_reading_unknown_metric_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.record_reading(ORG, "nonexistent-id", 42.0)


def test_record_reading_with_source_system(engine):
    m = engine.define_metric(ORG, {"name": "IOCs"})
    r = engine.record_reading(ORG, m["metric_id"], 5.0, source_system="threat_intel_feed")
    assert r["source_system"] == "threat_intel_feed"


def test_record_reading_with_period(engine):
    m = engine.define_metric(ORG, {"name": "Weekly Count"})
    r = engine.record_reading(
        ORG, m["metric_id"], 42.0,
        period_start="2026-04-07T00:00:00",
        period_end="2026-04-13T23:59:59",
    )
    assert r["period_start"] == "2026-04-07T00:00:00"
    assert r["period_end"] == "2026-04-13T23:59:59"


# ---------------------------------------------------------------------------
# list_readings
# ---------------------------------------------------------------------------

def test_list_readings_newest_first(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    engine.record_reading(ORG, m["metric_id"], 1.0)
    engine.record_reading(ORG, m["metric_id"], 2.0)
    engine.record_reading(ORG, m["metric_id"], 3.0)
    readings = engine.list_readings(ORG, m["metric_id"], limit=30)
    assert readings[0]["value"] == 3.0
    assert readings[-1]["value"] == 1.0


def test_list_readings_limit(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    for v in range(10):
        engine.record_reading(ORG, m["metric_id"], float(v))
    readings = engine.list_readings(ORG, m["metric_id"], limit=3)
    assert len(readings) == 3


def test_list_readings_org_isolation(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    readings_other = engine.list_readings(ORG2, m["metric_id"], limit=30)
    assert readings_other == []


# ---------------------------------------------------------------------------
# calculate_aggregate
# ---------------------------------------------------------------------------

def test_calculate_aggregate_daily(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    engine.record_reading(ORG, m["metric_id"], 10.0)
    engine.record_reading(ORG, m["metric_id"], 20.0)
    engine.record_reading(ORG, m["metric_id"], 30.0)
    agg = engine.calculate_aggregate(ORG, m["metric_id"], "daily")
    assert agg["agg_id"]
    assert agg["avg_value"] == pytest.approx(20.0)
    assert agg["min_value"] == pytest.approx(10.0)
    assert agg["max_value"] == pytest.approx(30.0)
    assert agg["readings_count"] == 3
    assert agg["period_type"] == "daily"


def test_calculate_aggregate_weekly(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    agg = engine.calculate_aggregate(ORG, m["metric_id"], "weekly")
    assert agg["period_type"] == "weekly"
    assert "W" in agg["period_label"]


def test_calculate_aggregate_monthly(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    agg = engine.calculate_aggregate(ORG, m["metric_id"], "monthly")
    assert agg["period_type"] == "monthly"


def test_calculate_aggregate_invalid_period_raises(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    with pytest.raises(ValueError, match="period_type"):
        engine.calculate_aggregate(ORG, m["metric_id"], "yearly")


def test_calculate_aggregate_unknown_metric_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.calculate_aggregate(ORG, "no-such-metric", "daily")


# ---------------------------------------------------------------------------
# list_aggregates
# ---------------------------------------------------------------------------

def test_list_aggregates_filter_by_metric(engine):
    m1 = engine.define_metric(ORG, {"name": "M1"})
    m2 = engine.define_metric(ORG, {"name": "M2"})
    engine.record_reading(ORG, m1["metric_id"], 1.0)
    engine.record_reading(ORG, m2["metric_id"], 2.0)
    engine.calculate_aggregate(ORG, m1["metric_id"], "daily")
    engine.calculate_aggregate(ORG, m2["metric_id"], "daily")

    aggs = engine.list_aggregates(ORG, metric_id=m1["metric_id"])
    assert len(aggs) == 1
    assert aggs[0]["metric_id"] == m1["metric_id"]


def test_list_aggregates_filter_by_period_type(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    engine.calculate_aggregate(ORG, m["metric_id"], "daily")
    engine.calculate_aggregate(ORG, m["metric_id"], "weekly")

    daily = engine.list_aggregates(ORG, period_type="daily")
    weekly = engine.list_aggregates(ORG, period_type="weekly")
    assert len(daily) == 1
    assert len(weekly) == 1


# ---------------------------------------------------------------------------
# list_alerts / acknowledge_alert
# ---------------------------------------------------------------------------

def test_list_alerts_unacknowledged_by_default(engine):
    m = engine.define_metric(ORG, {"name": "M", "critical_threshold": 1.0})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    alerts = engine.list_alerts(ORG, acknowledged=False)
    assert len(alerts) == 1
    assert alerts[0]["acknowledged"] == 0


def test_acknowledge_alert(engine):
    m = engine.define_metric(ORG, {"name": "M", "critical_threshold": 1.0})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    alerts = engine.list_alerts(ORG, acknowledged=False)
    alert_id = alerts[0]["alert_id"]

    result = engine.acknowledge_alert(ORG, alert_id)
    assert result is True

    unacked = engine.list_alerts(ORG, acknowledged=False)
    assert len(unacked) == 0
    acked = engine.list_alerts(ORG, acknowledged=True)
    assert len(acked) == 1


def test_acknowledge_alert_wrong_org_returns_false(engine):
    m = engine.define_metric(ORG, {"name": "M", "critical_threshold": 1.0})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    alerts = engine.list_alerts(ORG)
    result = engine.acknowledge_alert(ORG2, alerts[0]["alert_id"])
    assert result is False


def test_acknowledge_already_acknowledged_returns_false(engine):
    m = engine.define_metric(ORG, {"name": "M", "critical_threshold": 1.0})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    alerts = engine.list_alerts(ORG)
    alert_id = alerts[0]["alert_id"]
    engine.acknowledge_alert(ORG, alert_id)
    result = engine.acknowledge_alert(ORG, alert_id)
    assert result is False


def test_alerts_org_isolation(engine):
    m = engine.define_metric(ORG, {"name": "M", "critical_threshold": 1.0})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    alerts_other = engine.list_alerts(ORG2)
    assert alerts_other == []


# ---------------------------------------------------------------------------
# get_dashboard
# ---------------------------------------------------------------------------

def test_get_dashboard_empty(engine):
    dash = engine.get_dashboard(ORG)
    assert dash["total_metrics"] == 0
    assert dash["by_category"] == {}
    assert dash["critical_alerts"] == 0
    assert dash["warning_alerts"] == 0
    assert dash["unacknowledged_alerts"] == 0
    assert dash["top_5_worst_metrics"] == []


def test_get_dashboard_with_metrics(engine):
    m = engine.define_metric(ORG, {
        "name": "Open Vulns",
        "category": "vulnerability",
        "target_value": 0.0,
        "critical_threshold": 20.0,
        "warning_threshold": 10.0,
    })
    engine.record_reading(ORG, m["metric_id"], 25.0)

    dash = engine.get_dashboard(ORG)
    assert dash["total_metrics"] == 1
    assert "vulnerability" in dash["by_category"]
    assert len(dash["by_category"]["vulnerability"]) == 1
    assert dash["by_category"]["vulnerability"][0]["latest_value"] == 25.0
    assert dash["critical_alerts"] == 1
    assert dash["unacknowledged_alerts"] == 1


def test_get_dashboard_top_5_worst(engine):
    for i in range(7):
        m = engine.define_metric(ORG, {
            "name": f"Metric{i}",
            "target_value": 0.0,
        })
        engine.record_reading(ORG, m["metric_id"], float(i * 10))
    dash = engine.get_dashboard(ORG)
    assert len(dash["top_5_worst_metrics"]) == 5
    # Should be sorted descending by distance from target (0)
    distances = [x["distance_from_target"] for x in dash["top_5_worst_metrics"]]
    assert distances == sorted(distances, reverse=True)


def test_get_dashboard_org_isolation(engine):
    m = engine.define_metric(ORG, {"name": "M"})
    engine.record_reading(ORG, m["metric_id"], 5.0)
    dash2 = engine.get_dashboard(ORG2)
    assert dash2["total_metrics"] == 0
