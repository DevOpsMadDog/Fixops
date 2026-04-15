"""Tests for SecurityTelemetryEngine — 30+ tests."""

from __future__ import annotations

import time

import pytest
from core.security_telemetry_engine import SecurityTelemetryEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityTelemetryEngine(db_path=str(tmp_path / "st_test.db"))


ORG = "org-st-test"
ORG2 = "org-st-other"


def _dp(overrides=None):
    data = {
        "telemetry_type": "events_per_second",
        "source": "siem",
        "value": 42.0,
        "unit": "eps",
    }
    if overrides:
        data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# ingest_telemetry
# ---------------------------------------------------------------------------

def test_ingest_basic(engine):
    dp = engine.ingest_telemetry(ORG, _dp())
    assert dp["telemetry_type"] == "events_per_second"
    assert dp["source"] == "siem"
    assert dp["value"] == 42.0
    assert "id" in dp


def test_ingest_returns_uuid(engine):
    dp = engine.ingest_telemetry(ORG, _dp())
    assert len(dp["id"]) == 36


def test_ingest_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="telemetry_type"):
        engine.ingest_telemetry(ORG, _dp({"telemetry_type": "bad_metric"}))


def test_ingest_invalid_source_raises(engine):
    with pytest.raises(ValueError, match="source"):
        engine.ingest_telemetry(ORG, _dp({"source": "spaceship"}))


def test_ingest_all_valid_types(engine):
    types = [
        "events_per_second", "alert_volume", "false_positive_rate",
        "detection_latency", "mttr", "coverage_score", "threat_score", "noise_ratio",
    ]
    for t in types:
        dp = engine.ingest_telemetry(ORG, _dp({"telemetry_type": t}))
        assert dp["telemetry_type"] == t


def test_ingest_all_valid_sources(engine):
    sources = ["siem", "edr", "ndr", "firewall", "ids", "cloud", "custom"]
    for s in sources:
        dp = engine.ingest_telemetry(ORG, _dp({"source": s}))
        assert dp["source"] == s


# ---------------------------------------------------------------------------
# list_telemetry
# ---------------------------------------------------------------------------

def test_list_telemetry_empty(engine):
    assert engine.list_telemetry(ORG) == []


def test_list_telemetry_returns_all(engine):
    engine.ingest_telemetry(ORG, _dp())
    engine.ingest_telemetry(ORG, _dp({"value": 10.0}))
    assert len(engine.list_telemetry(ORG)) == 2


def test_list_telemetry_filter_type(engine):
    engine.ingest_telemetry(ORG, _dp({"telemetry_type": "alert_volume"}))
    engine.ingest_telemetry(ORG, _dp({"telemetry_type": "mttr"}))
    alerts = engine.list_telemetry(ORG, telemetry_type="alert_volume")
    assert len(alerts) == 1
    assert alerts[0]["telemetry_type"] == "alert_volume"


def test_list_telemetry_filter_source(engine):
    engine.ingest_telemetry(ORG, _dp({"source": "edr"}))
    engine.ingest_telemetry(ORG, _dp({"source": "ndr"}))
    edr = engine.list_telemetry(ORG, source="edr")
    assert len(edr) == 1


def test_list_telemetry_limit(engine):
    for i in range(10):
        engine.ingest_telemetry(ORG, _dp({"value": float(i)}))
    result = engine.list_telemetry(ORG, limit=3)
    assert len(result) == 3


def test_list_telemetry_org_isolation(engine):
    engine.ingest_telemetry(ORG, _dp())
    assert engine.list_telemetry(ORG2) == []


# ---------------------------------------------------------------------------
# get_latest
# ---------------------------------------------------------------------------

def test_get_latest_returns_most_recent(engine):
    engine.ingest_telemetry(ORG, _dp({"value": 10.0}))
    engine.ingest_telemetry(ORG, _dp({"value": 99.0}))
    latest = engine.get_latest(ORG, "events_per_second")
    assert latest is not None
    assert latest["value"] == 99.0


def test_get_latest_none_when_empty(engine):
    assert engine.get_latest(ORG, "events_per_second") is None


def test_get_latest_filter_by_source(engine):
    engine.ingest_telemetry(ORG, _dp({"value": 5.0, "source": "edr"}))
    engine.ingest_telemetry(ORG, _dp({"value": 50.0, "source": "siem"}))
    latest_edr = engine.get_latest(ORG, "events_per_second", source="edr")
    assert latest_edr["value"] == 5.0


def test_get_latest_org_isolation(engine):
    engine.ingest_telemetry(ORG, _dp())
    assert engine.get_latest(ORG2, "events_per_second") is None


# ---------------------------------------------------------------------------
# aggregate_telemetry
# ---------------------------------------------------------------------------

def test_aggregate_avg(engine):
    engine.ingest_telemetry(ORG, _dp({"value": 10.0}))
    engine.ingest_telemetry(ORG, _dp({"value": 20.0}))
    result = engine.aggregate_telemetry(ORG, "events_per_second", "avg", hours=24)
    assert result["value"] == pytest.approx(15.0)
    assert result["datapoint_count"] == 2


def test_aggregate_sum(engine):
    engine.ingest_telemetry(ORG, _dp({"value": 10.0}))
    engine.ingest_telemetry(ORG, _dp({"value": 20.0}))
    result = engine.aggregate_telemetry(ORG, "events_per_second", "sum", hours=24)
    assert result["value"] == pytest.approx(30.0)


def test_aggregate_max(engine):
    engine.ingest_telemetry(ORG, _dp({"value": 5.0}))
    engine.ingest_telemetry(ORG, _dp({"value": 95.0}))
    result = engine.aggregate_telemetry(ORG, "events_per_second", "max", hours=24)
    assert result["value"] == pytest.approx(95.0)


def test_aggregate_min(engine):
    engine.ingest_telemetry(ORG, _dp({"value": 5.0}))
    engine.ingest_telemetry(ORG, _dp({"value": 95.0}))
    result = engine.aggregate_telemetry(ORG, "events_per_second", "min", hours=24)
    assert result["value"] == pytest.approx(5.0)


def test_aggregate_count(engine):
    for _ in range(7):
        engine.ingest_telemetry(ORG, _dp())
    result = engine.aggregate_telemetry(ORG, "events_per_second", "count", hours=24)
    assert result["value"] == 7.0


def test_aggregate_p95(engine):
    for i in range(1, 101):
        engine.ingest_telemetry(ORG, _dp({"value": float(i)}))
    result = engine.aggregate_telemetry(ORG, "events_per_second", "p95", hours=24)
    assert result["value"] >= 94.0


def test_aggregate_p99(engine):
    for i in range(1, 101):
        engine.ingest_telemetry(ORG, _dp({"value": float(i)}))
    result = engine.aggregate_telemetry(ORG, "events_per_second", "p99", hours=24)
    assert result["value"] >= 98.0


def test_aggregate_invalid_aggregation_raises(engine):
    with pytest.raises(ValueError, match="aggregation"):
        engine.aggregate_telemetry(ORG, "events_per_second", "median", hours=24)


def test_aggregate_empty_returns_zero(engine):
    result = engine.aggregate_telemetry(ORG, "events_per_second", "avg", hours=24)
    assert result["value"] == 0.0
    assert result["datapoint_count"] == 0


def test_aggregate_returns_correct_keys(engine):
    result = engine.aggregate_telemetry(ORG, "events_per_second", "avg", hours=24)
    for key in ("telemetry_type", "aggregation", "value", "source", "hours", "datapoint_count"):
        assert key in result


# ---------------------------------------------------------------------------
# create_alert_rule
# ---------------------------------------------------------------------------

def test_create_rule_basic(engine):
    rule = engine.create_alert_rule(ORG, {
        "name": "High EPS",
        "telemetry_type": "events_per_second",
        "aggregation": "avg",
        "threshold": 1000.0,
        "operator": "gt",
    })
    assert rule["name"] == "High EPS"
    assert rule["enabled"] == 1
    assert rule["trigger_count"] == 0


def test_create_rule_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="telemetry_type"):
        engine.create_alert_rule(ORG, {
            "name": "bad", "telemetry_type": "bad_type",
            "aggregation": "avg", "threshold": 0, "operator": "gt",
        })


def test_create_rule_invalid_aggregation_raises(engine):
    with pytest.raises(ValueError, match="aggregation"):
        engine.create_alert_rule(ORG, {
            "name": "bad", "telemetry_type": "events_per_second",
            "aggregation": "mode", "threshold": 0, "operator": "gt",
        })


def test_create_rule_invalid_operator_raises(engine):
    with pytest.raises(ValueError, match="operator"):
        engine.create_alert_rule(ORG, {
            "name": "bad", "telemetry_type": "events_per_second",
            "aggregation": "avg", "threshold": 0, "operator": "eq",
        })


# ---------------------------------------------------------------------------
# list_alert_rules
# ---------------------------------------------------------------------------

def test_list_rules_empty(engine):
    assert engine.list_alert_rules(ORG) == []


def test_list_rules_returns_created(engine):
    engine.create_alert_rule(ORG, {
        "name": "r1", "telemetry_type": "alert_volume",
        "aggregation": "sum", "threshold": 500, "operator": "gt",
    })
    rules = engine.list_alert_rules(ORG)
    assert len(rules) == 1


def test_list_rules_filter_enabled(engine):
    engine.create_alert_rule(ORG, {
        "name": "r1", "telemetry_type": "events_per_second",
        "aggregation": "avg", "threshold": 100, "operator": "gt",
    })
    enabled = engine.list_alert_rules(ORG, enabled=True)
    assert len(enabled) == 1
    disabled = engine.list_alert_rules(ORG, enabled=False)
    assert len(disabled) == 0


def test_list_rules_org_isolation(engine):
    engine.create_alert_rule(ORG, {
        "name": "r1", "telemetry_type": "events_per_second",
        "aggregation": "avg", "threshold": 100, "operator": "gt",
    })
    assert engine.list_alert_rules(ORG2) == []


# ---------------------------------------------------------------------------
# check_alert_rules
# ---------------------------------------------------------------------------

def test_check_rules_triggers_gt(engine):
    # Ingest value above threshold
    engine.ingest_telemetry(ORG, _dp({"value": 999.0}))
    engine.create_alert_rule(ORG, {
        "name": "GT rule", "telemetry_type": "events_per_second",
        "aggregation": "avg", "threshold": 100.0, "operator": "gt",
    })
    triggered = engine.check_alert_rules(ORG)
    assert len(triggered) == 1
    assert triggered[0]["name"] == "GT rule"
    assert "current_value" in triggered[0]


def test_check_rules_no_trigger_below_threshold(engine):
    engine.ingest_telemetry(ORG, _dp({"value": 10.0}))
    engine.create_alert_rule(ORG, {
        "name": "GT rule", "telemetry_type": "events_per_second",
        "aggregation": "avg", "threshold": 100.0, "operator": "gt",
    })
    triggered = engine.check_alert_rules(ORG)
    assert len(triggered) == 0


def test_check_rules_increments_trigger_count(engine):
    engine.ingest_telemetry(ORG, _dp({"value": 999.0}))
    engine.create_alert_rule(ORG, {
        "name": "r", "telemetry_type": "events_per_second",
        "aggregation": "avg", "threshold": 100.0, "operator": "gt",
    })
    engine.check_alert_rules(ORG)
    rules = engine.list_alert_rules(ORG)
    assert rules[0]["trigger_count"] == 1


def test_check_rules_lt_operator(engine):
    engine.ingest_telemetry(ORG, _dp({"telemetry_type": "coverage_score", "value": 30.0, "source": "siem"}))
    engine.create_alert_rule(ORG, {
        "name": "Low coverage", "telemetry_type": "coverage_score",
        "aggregation": "avg", "threshold": 50.0, "operator": "lt", "source": "siem",
    })
    triggered = engine.check_alert_rules(ORG)
    assert len(triggered) == 1


def test_check_rules_empty_no_trigger(engine):
    engine.create_alert_rule(ORG, {
        "name": "r", "telemetry_type": "events_per_second",
        "aggregation": "avg", "threshold": 0.0, "operator": "gt",
    })
    # No data ingested — aggregate returns 0.0, not > 0.0
    triggered = engine.check_alert_rules(ORG)
    assert len(triggered) == 0


# ---------------------------------------------------------------------------
# get_telemetry_stats
# ---------------------------------------------------------------------------

def test_stats_empty(engine):
    stats = engine.get_telemetry_stats(ORG)
    assert stats["total_datapoints"] == 0
    assert stats["active_sources"] == 0
    assert stats["telemetry_types_tracked"] == 0
    assert stats["alert_rules_count"] == 0
    assert stats["triggered_rules_today"] == 0
    assert stats["by_type"] == {}


def test_stats_counts(engine):
    engine.ingest_telemetry(ORG, _dp({"source": "edr"}))
    engine.ingest_telemetry(ORG, _dp({"telemetry_type": "alert_volume", "source": "ndr"}))
    stats = engine.get_telemetry_stats(ORG)
    assert stats["total_datapoints"] == 2
    assert stats["active_sources"] == 2
    assert stats["telemetry_types_tracked"] == 2


def test_stats_by_type(engine):
    engine.ingest_telemetry(ORG, _dp({"telemetry_type": "mttr"}))
    engine.ingest_telemetry(ORG, _dp({"telemetry_type": "mttr"}))
    engine.ingest_telemetry(ORG, _dp({"telemetry_type": "alert_volume"}))
    stats = engine.get_telemetry_stats(ORG)
    assert stats["by_type"]["mttr"] == 2
    assert stats["by_type"]["alert_volume"] == 1


def test_stats_alert_rules_count(engine):
    engine.create_alert_rule(ORG, {
        "name": "r1", "telemetry_type": "events_per_second",
        "aggregation": "avg", "threshold": 100, "operator": "gt",
    })
    engine.create_alert_rule(ORG, {
        "name": "r2", "telemetry_type": "mttr",
        "aggregation": "avg", "threshold": 3600, "operator": "gt",
    })
    stats = engine.get_telemetry_stats(ORG)
    assert stats["alert_rules_count"] == 2


def test_stats_org_isolation(engine):
    engine.ingest_telemetry(ORG, _dp())
    stats = engine.get_telemetry_stats(ORG2)
    assert stats["total_datapoints"] == 0
