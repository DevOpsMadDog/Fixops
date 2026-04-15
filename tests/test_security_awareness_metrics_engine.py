"""Tests for SecurityAwarenessMetricsEngine.

Covers metric recording, filtering, trend computation, benchmark UPSERT,
and aggregate statistics.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.security_awareness_metrics_engine import SecurityAwarenessMetricsEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "sam_test.db")
    return SecurityAwarenessMetricsEngine(db_path=db)


@pytest.fixture()
def metric_eng(engine):
    return engine.record_metric("org1", {
        "metric_type": "training_completion",
        "department": "Engineering",
        "value": 85.0,
        "period": "2024-Q1",
        "sample_size": 50,
    })


@pytest.fixture()
def metric_sales(engine):
    return engine.record_metric("org1", {
        "metric_type": "phishing_click_rate",
        "department": "Sales",
        "value": 12.5,
        "period": "2024-Q1",
        "sample_size": 40,
    })


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "sam_init.db")
    SecurityAwarenessMetricsEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "sam_idem.db")
    SecurityAwarenessMetricsEngine(db_path=db)
    SecurityAwarenessMetricsEngine(db_path=db)


# ===========================================================================
# 2. record_metric
# ===========================================================================

def test_record_metric_returns_record(engine, metric_eng):
    assert "id" in metric_eng
    assert metric_eng["metric_type"] == "training_completion"
    assert metric_eng["department"] == "Engineering"
    assert metric_eng["value"] == 85.0


def test_record_metric_sets_recorded_at(engine, metric_eng):
    assert metric_eng["recorded_at"] is not None


def test_record_metric_all_valid_types(engine):
    valid_types = [
        "phishing_click_rate", "training_completion", "quiz_score",
        "policy_acknowledgement", "incident_report_rate", "password_strength",
    ]
    for mt in valid_types:
        m = engine.record_metric("org1", {"metric_type": mt, "value": 50.0})
        assert m["metric_type"] == mt


def test_record_metric_invalid_type(engine):
    with pytest.raises(ValueError, match="metric_type"):
        engine.record_metric("org1", {"metric_type": "invalid_metric", "value": 50.0})


def test_record_metric_default_department(engine):
    m = engine.record_metric("org1", {"metric_type": "quiz_score", "value": 70.0})
    assert m["department"] == "all"


def test_record_metric_sample_size(engine):
    m = engine.record_metric("org1", {
        "metric_type": "policy_acknowledgement",
        "value": 90.0,
        "sample_size": 100,
    })
    assert m["sample_size"] == 100


# ===========================================================================
# 3. list_metrics
# ===========================================================================

def test_list_metrics_all(engine, metric_eng, metric_sales):
    metrics = engine.list_metrics("org1")
    assert len(metrics) == 2


def test_list_metrics_filter_type(engine, metric_eng, metric_sales):
    metrics = engine.list_metrics("org1", metric_type="training_completion")
    assert len(metrics) == 1
    assert metrics[0]["metric_type"] == "training_completion"


def test_list_metrics_filter_department(engine, metric_eng, metric_sales):
    metrics = engine.list_metrics("org1", department="Sales")
    assert len(metrics) == 1
    assert metrics[0]["department"] == "Sales"


def test_list_metrics_org_isolation(engine, metric_eng):
    metrics = engine.list_metrics("org2")
    assert len(metrics) == 0


def test_list_metrics_ordered_newest_first(engine):
    engine.record_metric("org1", {"metric_type": "quiz_score", "value": 60.0, "period": "2024-Q1"})
    engine.record_metric("org1", {"metric_type": "quiz_score", "value": 75.0, "period": "2024-Q2"})
    metrics = engine.list_metrics("org1", metric_type="quiz_score")
    # newest (Q2) should come first
    assert metrics[0]["value"] == 75.0


# ===========================================================================
# 4. get_latest_metric
# ===========================================================================

def test_get_latest_metric_returns_most_recent(engine):
    engine.record_metric("org1", {"metric_type": "quiz_score", "department": "HR", "value": 60.0})
    engine.record_metric("org1", {"metric_type": "quiz_score", "department": "HR", "value": 80.0})
    latest = engine.get_latest_metric("org1", "quiz_score", department="HR")
    assert latest["value"] == 80.0


def test_get_latest_metric_without_department(engine):
    engine.record_metric("org1", {"metric_type": "password_strength", "value": 70.0})
    latest = engine.get_latest_metric("org1", "password_strength")
    assert latest is not None


def test_get_latest_metric_missing_returns_none(engine):
    result = engine.get_latest_metric("org1", "phishing_click_rate")
    assert result is None


def test_get_latest_metric_org_isolation(engine, metric_eng):
    result = engine.get_latest_metric("org2", "training_completion")
    assert result is None


# ===========================================================================
# 5. get_trend
# ===========================================================================

def test_get_trend_improving(engine):
    for v in [50.0, 60.0, 70.0, 80.0]:
        engine.record_metric("org1", {"metric_type": "training_completion", "department": "Dev", "value": v})
    trend = engine.get_trend("org1", "training_completion", department="Dev", periods=4)
    assert trend["trend"] == "improving"


def test_get_trend_declining(engine):
    for v in [80.0, 70.0, 60.0, 50.0]:
        engine.record_metric("org1", {"metric_type": "phishing_click_rate", "department": "Dev", "value": v})
    trend = engine.get_trend("org1", "phishing_click_rate", department="Dev", periods=4)
    assert trend["trend"] == "declining"


def test_get_trend_stable(engine):
    for _ in range(3):
        engine.record_metric("org1", {"metric_type": "quiz_score", "department": "QA", "value": 75.0})
    trend = engine.get_trend("org1", "quiz_score", department="QA", periods=3)
    assert trend["trend"] == "stable"


def test_get_trend_returns_records(engine):
    for v in [40.0, 50.0, 60.0]:
        engine.record_metric("org1", {"metric_type": "policy_acknowledgement", "value": v})
    result = engine.get_trend("org1", "policy_acknowledgement", periods=3)
    assert len(result["records"]) == 3


def test_get_trend_insufficient_data_stable(engine):
    engine.record_metric("org1", {"metric_type": "incident_report_rate", "value": 55.0})
    trend = engine.get_trend("org1", "incident_report_rate", periods=4)
    assert trend["trend"] == "stable"


# ===========================================================================
# 6. set_benchmark / list_benchmarks
# ===========================================================================

def test_set_benchmark_creates_record(engine):
    bm = engine.set_benchmark("org1", {
        "metric_type": "training_completion",
        "target_value": 90.0,
        "industry_average": 75.0,
        "period": "2024",
    })
    assert bm["target_value"] == 90.0
    assert bm["industry_average"] == 75.0


def test_set_benchmark_upsert_updates_not_inserts(engine):
    engine.set_benchmark("org1", {
        "metric_type": "training_completion",
        "target_value": 85.0,
        "industry_average": 70.0,
    })
    engine.set_benchmark("org1", {
        "metric_type": "training_completion",
        "target_value": 92.0,
        "industry_average": 78.0,
    })
    bms = engine.list_benchmarks("org1")
    # should still be exactly 1 benchmark for this metric_type
    tc_bms = [b for b in bms if b["metric_type"] == "training_completion"]
    assert len(tc_bms) == 1
    assert tc_bms[0]["target_value"] == 92.0


def test_set_benchmark_invalid_type(engine):
    with pytest.raises(ValueError, match="metric_type"):
        engine.set_benchmark("org1", {"metric_type": "not_a_metric", "target_value": 80.0})


def test_list_benchmarks_multiple(engine):
    engine.set_benchmark("org1", {"metric_type": "training_completion", "target_value": 90.0, "industry_average": 75.0})
    engine.set_benchmark("org1", {"metric_type": "phishing_click_rate", "target_value": 5.0, "industry_average": 15.0})
    bms = engine.list_benchmarks("org1")
    assert len(bms) == 2


def test_list_benchmarks_org_isolation(engine):
    engine.set_benchmark("org1", {"metric_type": "quiz_score", "target_value": 80.0, "industry_average": 65.0})
    bms = engine.list_benchmarks("org2")
    assert len(bms) == 0


# ===========================================================================
# 7. get_awareness_stats
# ===========================================================================

def test_stats_total_metrics(engine, metric_eng, metric_sales):
    stats = engine.get_awareness_stats("org1")
    assert stats["total_metrics"] == 2


def test_stats_unique_departments(engine, metric_eng, metric_sales):
    stats = engine.get_awareness_stats("org1")
    assert stats["unique_departments"] == 2


def test_stats_metrics_by_type(engine, metric_eng, metric_sales):
    stats = engine.get_awareness_stats("org1")
    assert "training_completion" in stats["metrics_by_type"]
    assert "phishing_click_rate" in stats["metrics_by_type"]


def test_stats_best_and_worst_metric(engine):
    engine.record_metric("org1", {"metric_type": "training_completion", "value": 90.0})
    engine.record_metric("org1", {"metric_type": "phishing_click_rate", "value": 10.0})
    stats = engine.get_awareness_stats("org1")
    assert stats["best_metric"] == "training_completion"
    assert stats["worst_metric"] == "phishing_click_rate"


def test_stats_departments_below_benchmark(engine):
    engine.record_metric("org1", {
        "metric_type": "training_completion",
        "department": "Sales",
        "value": 60.0,
    })
    engine.set_benchmark("org1", {
        "metric_type": "training_completion",
        "target_value": 80.0,
        "industry_average": 70.0,
    })
    stats = engine.get_awareness_stats("org1")
    # Sales at 60 is below target of 80
    assert any("Sales" in entry for entry in stats["departments_below_benchmark"])


def test_stats_empty_org(engine):
    stats = engine.get_awareness_stats("empty_org")
    assert stats["total_metrics"] == 0
    assert stats["best_metric"] is None
    assert stats["worst_metric"] is None
