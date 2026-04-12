"""
Tests for MetricsAggregator — ALDECI.

Covers:
- All 7 category collectors return proper Metric objects
- collect_all_metrics returns all categories
- Snapshot persistence and retrieval
- Metric history
- Period comparison
- Health check
- Single metric lookup
- get_category_metrics filtering

At least 25 tests, all passing.

Compliance: SOC2 CC7.2 test coverage
"""

from __future__ import annotations

import sys
import json
import pytest
import tempfile
import os
from datetime import datetime, timedelta, timezone
from typing import List

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.metrics_aggregator import (
    Metric,
    MetricCategory,
    MetricTrend,
    MetricsAggregator,
    MetricsSnapshot,
    get_metrics_aggregator,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path) -> str:
    return str(tmp_path / "test_metrics.db")


@pytest.fixture
def aggregator(tmp_db: str) -> MetricsAggregator:
    return MetricsAggregator(db_path=tmp_db)


@pytest.fixture
def mem_aggregator() -> MetricsAggregator:
    return MetricsAggregator(db_path=":memory:")


def _make_metric(
    name: str = "test_metric",
    value: float = 42.0,
    unit: str = "count",
    category: MetricCategory = MetricCategory.POSTURE,
    trend: MetricTrend = MetricTrend.STABLE,
    change_pct: float = 0.0,
    period: str = "current",
) -> Metric:
    return Metric(
        name=name,
        value=value,
        unit=unit,
        category=category,
        trend=trend,
        change_pct=change_pct,
        period=period,
    )


def _make_snapshot(org_id: str = "test-org", metrics: List[Metric] | None = None) -> MetricsSnapshot:
    if metrics is None:
        metrics = [_make_metric()]
    return MetricsSnapshot(org_id=org_id, metrics=metrics, summary={"total_metrics": len(metrics)})


# ============================================================================
# MODEL TESTS
# ============================================================================


class TestMetricModel:
    def test_metric_creation_defaults(self) -> None:
        m = Metric(name="test", value=10.0, category=MetricCategory.POSTURE)
        assert m.name == "test"
        assert m.value == 10.0
        assert m.unit == ""
        assert m.trend == MetricTrend.STABLE
        assert m.change_pct == 0.0
        assert m.period == "current"

    def test_metric_all_fields(self) -> None:
        m = Metric(
            name="vuln_count",
            value=99.5,
            unit="count",
            category=MetricCategory.VULNERABILITY,
            trend=MetricTrend.UP,
            change_pct=12.5,
            period="last_30d",
        )
        assert m.name == "vuln_count"
        assert m.value == 99.5
        assert m.unit == "count"
        assert m.category == MetricCategory.VULNERABILITY
        assert m.trend == MetricTrend.UP
        assert m.change_pct == 12.5
        assert m.period == "last_30d"

    def test_metric_trend_values(self) -> None:
        for trend in MetricTrend:
            m = Metric(name="t", value=1.0, category=MetricCategory.SLA, trend=trend)
            assert m.trend == trend

    def test_metric_category_values(self) -> None:
        for cat in MetricCategory:
            m = Metric(name="c", value=0.0, category=cat)
            assert m.category == cat


class TestMetricsSnapshotModel:
    def test_snapshot_has_id(self) -> None:
        s = _make_snapshot()
        assert s.id.startswith("ms-")
        assert len(s.id) > 5

    def test_snapshot_timestamp_is_utc_iso(self) -> None:
        s = _make_snapshot()
        dt = datetime.fromisoformat(s.timestamp)
        assert dt.tzinfo is not None

    def test_snapshot_metrics_list(self) -> None:
        metrics = [_make_metric(name=f"m{i}") for i in range(5)]
        s = MetricsSnapshot(org_id="org1", metrics=metrics, summary={})
        assert len(s.metrics) == 5

    def test_snapshot_empty_metrics(self) -> None:
        s = MetricsSnapshot(org_id="org1", metrics=[], summary={})
        assert s.metrics == []


# ============================================================================
# PERSISTENCE TESTS
# ============================================================================


class TestSnapshotPersistence:
    def test_store_and_retrieve_snapshot(self, aggregator: MetricsAggregator) -> None:
        snap = _make_snapshot("org-persist")
        aggregator.store_snapshot(snap)
        retrieved = aggregator.get_latest_snapshot("org-persist")
        assert retrieved is not None
        assert retrieved.org_id == "org-persist"

    def test_get_latest_returns_most_recent(self, aggregator: MetricsAggregator) -> None:
        snap1 = MetricsSnapshot(
            org_id="org-latest",
            metrics=[_make_metric(name="m1", value=10.0)],
            summary={},
            timestamp=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        )
        snap2 = MetricsSnapshot(
            org_id="org-latest",
            metrics=[_make_metric(name="m1", value=99.0)],
            summary={},
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        aggregator.store_snapshot(snap1)
        aggregator.store_snapshot(snap2)
        retrieved = aggregator.get_latest_snapshot("org-latest")
        assert retrieved is not None
        assert retrieved.metrics[0].value == 99.0

    def test_get_latest_returns_none_for_unknown_org(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_latest_snapshot("unknown-org-xyz")
        assert result is None

    def test_snapshot_persists_all_metrics(self, aggregator: MetricsAggregator) -> None:
        metrics = [
            _make_metric(name="posture_score", value=85.0, category=MetricCategory.POSTURE),
            _make_metric(name="vuln_open", value=12.0, category=MetricCategory.VULNERABILITY),
            _make_metric(name="sla_rate", value=95.0, category=MetricCategory.SLA),
        ]
        snap = _make_snapshot("org-multi", metrics=metrics)
        aggregator.store_snapshot(snap)
        retrieved = aggregator.get_latest_snapshot("org-multi")
        assert retrieved is not None
        assert len(retrieved.metrics) == 3
        names = {m.name for m in retrieved.metrics}
        assert names == {"posture_score", "vuln_open", "sla_rate"}

    def test_snapshot_summary_persisted(self, aggregator: MetricsAggregator) -> None:
        snap = MetricsSnapshot(
            org_id="org-summary",
            metrics=[],
            summary={"total_metrics": 0, "categories": {}},
        )
        aggregator.store_snapshot(snap)
        retrieved = aggregator.get_latest_snapshot("org-summary")
        assert retrieved is not None
        assert retrieved.summary["total_metrics"] == 0


# ============================================================================
# CATEGORY COLLECTOR TESTS
# ============================================================================


class TestCategoryCollectors:
    """Validate that each category collector returns Metric objects with correct fields."""

    def test_posture_metrics_returns_list(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_posture_metrics("test-org")
        assert isinstance(metrics, list)
        assert len(metrics) > 0

    def test_posture_metrics_have_correct_category(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_posture_metrics("test-org")
        for m in metrics:
            assert m.category == MetricCategory.POSTURE

    def test_vulnerability_metrics_returns_list(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_vulnerability_metrics("test-org")
        assert isinstance(metrics, list)
        assert len(metrics) > 0

    def test_vulnerability_metrics_have_correct_category(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_vulnerability_metrics("test-org")
        for m in metrics:
            assert m.category == MetricCategory.VULNERABILITY

    def test_compliance_metrics_returns_list(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_compliance_metrics("test-org")
        assert isinstance(metrics, list)
        assert len(metrics) > 0

    def test_compliance_metrics_have_correct_category(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_compliance_metrics("test-org")
        for m in metrics:
            assert m.category == MetricCategory.COMPLIANCE

    def test_sla_metrics_returns_list(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_sla_metrics("test-org")
        assert isinstance(metrics, list)
        assert len(metrics) > 0

    def test_sla_metrics_have_correct_category(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_sla_metrics("test-org")
        for m in metrics:
            assert m.category == MetricCategory.SLA

    def test_attack_surface_metrics_returns_list(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_attack_surface_metrics("test-org")
        assert isinstance(metrics, list)
        assert len(metrics) > 0

    def test_attack_surface_metrics_have_correct_category(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_attack_surface_metrics("test-org")
        for m in metrics:
            assert m.category == MetricCategory.ATTACK_SURFACE

    def test_scanner_metrics_returns_list(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_scanner_metrics("test-org")
        assert isinstance(metrics, list)
        assert len(metrics) > 0

    def test_scanner_metrics_have_correct_category(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_scanner_metrics("test-org")
        for m in metrics:
            assert m.category == MetricCategory.SCANNER

    def test_operational_metrics_returns_list(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_operational_metrics("test-org")
        assert isinstance(metrics, list)
        assert len(metrics) > 0

    def test_operational_metrics_have_correct_category(self, aggregator: MetricsAggregator) -> None:
        metrics = aggregator._collect_operational_metrics("test-org")
        for m in metrics:
            assert m.category == MetricCategory.OPERATIONAL

    def test_all_metrics_have_name_and_value(self, aggregator: MetricsAggregator) -> None:
        """Every metric returned by any collector has a non-empty name and numeric value."""
        collectors = [
            aggregator._collect_posture_metrics,
            aggregator._collect_vulnerability_metrics,
            aggregator._collect_compliance_metrics,
            aggregator._collect_sla_metrics,
            aggregator._collect_attack_surface_metrics,
            aggregator._collect_scanner_metrics,
            aggregator._collect_operational_metrics,
        ]
        for collector in collectors:
            for m in collector("test-org"):
                assert m.name, f"Empty metric name from {collector}"
                assert isinstance(m.value, (int, float))


# ============================================================================
# COLLECT ALL METRICS TESTS
# ============================================================================


class TestCollectAllMetrics:
    def test_collect_all_returns_snapshot(self, aggregator: MetricsAggregator) -> None:
        snapshot = aggregator.collect_all_metrics("test-org")
        assert isinstance(snapshot, MetricsSnapshot)

    def test_collect_all_has_all_7_categories(self, aggregator: MetricsAggregator) -> None:
        snapshot = aggregator.collect_all_metrics("test-org")
        present_categories = {m.category for m in snapshot.metrics}
        expected = {
            MetricCategory.POSTURE,
            MetricCategory.VULNERABILITY,
            MetricCategory.COMPLIANCE,
            MetricCategory.SLA,
            MetricCategory.ATTACK_SURFACE,
            MetricCategory.SCANNER,
            MetricCategory.OPERATIONAL,
        }
        assert expected == present_categories

    def test_collect_all_persists_snapshot(self, aggregator: MetricsAggregator) -> None:
        snapshot = aggregator.collect_all_metrics("org-persist-test")
        stored = aggregator.get_latest_snapshot("org-persist-test")
        assert stored is not None
        assert stored.id == snapshot.id

    def test_collect_all_has_summary(self, aggregator: MetricsAggregator) -> None:
        snapshot = aggregator.collect_all_metrics("test-org")
        assert "total_metrics" in snapshot.summary
        assert snapshot.summary["total_metrics"] == len(snapshot.metrics)

    def test_collect_all_org_id_matches(self, aggregator: MetricsAggregator) -> None:
        org = "specific-org-abc"
        snapshot = aggregator.collect_all_metrics(org)
        assert snapshot.org_id == org


# ============================================================================
# GET METRIC TESTS
# ============================================================================


class TestGetMetric:
    def test_get_metric_returns_correct_metric(self, aggregator: MetricsAggregator) -> None:
        snap = _make_snapshot(metrics=[
            _make_metric(name="posture_overall_score", value=78.5, category=MetricCategory.POSTURE),
            _make_metric(name="vuln_total_open", value=5.0, category=MetricCategory.VULNERABILITY),
        ])
        aggregator.store_snapshot(snap)
        metric = aggregator.get_metric("test-org", "posture_overall_score")
        assert metric is not None
        assert metric.name == "posture_overall_score"
        assert metric.value == 78.5

    def test_get_metric_returns_none_for_missing(self, aggregator: MetricsAggregator) -> None:
        snap = _make_snapshot(metrics=[_make_metric(name="some_metric")])
        aggregator.store_snapshot(snap)
        result = aggregator.get_metric("test-org", "nonexistent_metric")
        assert result is None

    def test_get_metric_returns_none_when_no_snapshot(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_metric("org-no-data", "any_metric")
        assert result is None


# ============================================================================
# GET CATEGORY METRICS TESTS
# ============================================================================


class TestGetCategoryMetrics:
    def test_get_category_filters_correctly(self, aggregator: MetricsAggregator) -> None:
        snap = _make_snapshot(metrics=[
            _make_metric(name="p1", category=MetricCategory.POSTURE),
            _make_metric(name="p2", category=MetricCategory.POSTURE),
            _make_metric(name="v1", category=MetricCategory.VULNERABILITY),
        ])
        aggregator.store_snapshot(snap)
        posture_metrics = aggregator.get_category_metrics("test-org", MetricCategory.POSTURE)
        assert len(posture_metrics) == 2
        assert all(m.category == MetricCategory.POSTURE for m in posture_metrics)

    def test_get_category_returns_empty_for_missing_org(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_category_metrics("org-not-exist", MetricCategory.SLA)
        assert result == []

    def test_get_category_returns_empty_for_absent_category(self, aggregator: MetricsAggregator) -> None:
        snap = _make_snapshot(metrics=[_make_metric(category=MetricCategory.POSTURE)])
        aggregator.store_snapshot(snap)
        result = aggregator.get_category_metrics("test-org", MetricCategory.OPERATIONAL)
        assert result == []


# ============================================================================
# METRICS HISTORY TESTS
# ============================================================================


class TestMetricsHistory:
    def test_history_returns_list(self, aggregator: MetricsAggregator) -> None:
        aggregator.collect_all_metrics("hist-org")
        history = aggregator.get_metrics_history("hist-org", "posture_overall_score", days=30)
        assert isinstance(history, list)

    def test_history_entries_have_timestamp_and_value(self, aggregator: MetricsAggregator) -> None:
        aggregator.collect_all_metrics("hist-org2")
        history = aggregator.get_metrics_history("hist-org2", "posture_overall_score", days=30)
        for entry in history:
            assert "timestamp" in entry
            assert "value" in entry

    def test_history_empty_for_unknown_metric(self, aggregator: MetricsAggregator) -> None:
        aggregator.collect_all_metrics("hist-org3")
        history = aggregator.get_metrics_history("hist-org3", "nonexistent_xyz", days=30)
        assert history == []

    def test_history_multiple_snapshots(self, aggregator: MetricsAggregator) -> None:
        # Store two snapshots at different times
        now = datetime.now(timezone.utc)
        snap1 = MetricsSnapshot(
            org_id="hist-multi",
            metrics=[_make_metric(name="posture_overall_score", value=70.0, category=MetricCategory.POSTURE)],
            summary={},
            timestamp=(now - timedelta(hours=5)).isoformat(),
        )
        snap2 = MetricsSnapshot(
            org_id="hist-multi",
            metrics=[_make_metric(name="posture_overall_score", value=80.0, category=MetricCategory.POSTURE)],
            summary={},
            timestamp=now.isoformat(),
        )
        aggregator.store_snapshot(snap1)
        aggregator.store_snapshot(snap2)
        history = aggregator.get_metrics_history("hist-multi", "posture_overall_score", days=1)
        assert len(history) == 2
        values = [h["value"] for h in history]
        assert 70.0 in values
        assert 80.0 in values


# ============================================================================
# PERIOD COMPARISON TESTS
# ============================================================================


class TestComparePeriods:
    def test_compare_returns_dict(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.compare_periods("cmp-org", current_days=7, previous_days=7)
        assert isinstance(result, dict)

    def test_compare_has_required_keys(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.compare_periods("cmp-org", current_days=7, previous_days=7)
        assert "org_id" in result
        assert "current_period_days" in result
        assert "previous_period_days" in result
        assert "generated_at" in result
        assert "comparisons" in result

    def test_compare_org_id_matches(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.compare_periods("cmp-org2")
        assert result["org_id"] == "cmp-org2"

    def test_compare_comparisons_has_key_metrics(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.compare_periods("cmp-org3")
        comparisons = result["comparisons"]
        assert "posture_overall_score" in comparisons

    def test_compare_period_days_set_correctly(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.compare_periods("cmp-org4", current_days=14, previous_days=30)
        assert result["current_period_days"] == 14
        assert result["previous_period_days"] == 30


# ============================================================================
# HEALTH CHECK TESTS
# ============================================================================


class TestHealthCheck:
    def test_health_check_returns_dict(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_health_check("health-org")
        assert isinstance(result, dict)

    def test_health_check_has_required_keys(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_health_check("health-org")
        assert "org_id" in result
        assert "healthy" in result
        assert "checked_at" in result
        assert "data_freshness" in result
        assert "services" in result

    def test_health_check_org_id_matches(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_health_check("health-org2")
        assert result["org_id"] == "health-org2"

    def test_health_check_no_snapshot_is_not_fresh(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_health_check("no-data-org-xyz")
        assert result["data_freshness"]["has_snapshot"] is False
        assert result["data_freshness"]["fresh"] is False

    def test_health_check_with_fresh_snapshot(self, aggregator: MetricsAggregator) -> None:
        # Store a fresh snapshot
        snap = _make_snapshot("fresh-org")
        aggregator.store_snapshot(snap)
        result = aggregator.get_health_check("fresh-org")
        assert result["data_freshness"]["has_snapshot"] is True
        assert result["data_freshness"]["fresh"] is True

    def test_health_check_services_dict(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_health_check("health-org3")
        services = result["services"]
        assert isinstance(services, dict)
        # All known subsystems should be checked
        for svc in ["posture_scoring", "vulnerability_analytics", "sla_manager", "attack_surface"]:
            assert svc in services
            assert services[svc] in ("ok", "unavailable")

    def test_health_checked_at_is_recent(self, aggregator: MetricsAggregator) -> None:
        result = aggregator.get_health_check("health-org4")
        checked_at = datetime.fromisoformat(result["checked_at"])
        now = datetime.now(timezone.utc)
        assert abs((now - checked_at).total_seconds()) < 10


# ============================================================================
# SINGLETON FACTORY TEST
# ============================================================================


class TestSingletonFactory:
    def test_get_metrics_aggregator_returns_instance(self) -> None:
        agg = get_metrics_aggregator(db_path=":memory:")
        assert isinstance(agg, MetricsAggregator)

    def test_get_metrics_aggregator_is_singleton(self) -> None:
        # Calling without args returns same instance as prior call
        agg1 = get_metrics_aggregator()
        agg2 = get_metrics_aggregator()
        assert agg1 is agg2
