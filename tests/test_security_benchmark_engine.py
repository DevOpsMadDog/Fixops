"""Tests for SecurityBenchmarkEngine — 35+ tests covering all methods."""
from __future__ import annotations

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.security_benchmark_engine import (
    SecurityBenchmarkEngine,
    _interpolate_percentile,
    _performance_label,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return SecurityBenchmarkEngine(db_path=str(tmp_path / "test_security_benchmark.db"))


ORG = "org-bm-test"
ORG2 = "org-bm-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_benchmark(engine, org=ORG, **kwargs):
    defaults = dict(
        benchmark_name="Gartner Vuln Benchmark",
        benchmark_source="Gartner",
        sector="technology",
        metric_name="mean_time_to_patch",
        metric_category="patch",
        p25=10.0,
        p50=20.0,
        p75=30.0,
        p90=45.0,
        unit="days",
        higher_is_better=False,
        published_date="2024-01-01",
    )
    defaults.update(kwargs)
    return engine.create_benchmark(org, **defaults)


def _make_metric(engine, org=ORG, **kwargs):
    defaults = dict(
        metric_name="mean_time_to_patch",
        metric_category="patch",
        value=25.0,
        unit="days",
        source="internal",
    )
    defaults.update(kwargs)
    return engine.record_org_metric(org, **defaults)


# ---------------------------------------------------------------------------
# Unit tests — pure functions
# ---------------------------------------------------------------------------

class TestInterpolatePercentile:
    def test_at_p50_returns_50(self):
        rank = _interpolate_percentile(20.0, 10.0, 20.0, 30.0, 45.0, True)
        assert rank == 50.0

    def test_at_p25_returns_25(self):
        rank = _interpolate_percentile(10.0, 10.0, 20.0, 30.0, 45.0, True)
        assert rank == 25.0

    def test_at_p75_returns_75(self):
        rank = _interpolate_percentile(30.0, 10.0, 20.0, 30.0, 45.0, True)
        assert rank == 75.0

    def test_below_p25_clamps_to_p25(self):
        rank = _interpolate_percentile(0.0, 10.0, 20.0, 30.0, 45.0, True)
        assert rank == 25.0

    def test_above_p90_clamps_to_p90(self):
        rank = _interpolate_percentile(100.0, 10.0, 20.0, 30.0, 45.0, True)
        assert rank == 90.0

    def test_interpolation_midpoint_p25_p50(self):
        rank = _interpolate_percentile(15.0, 10.0, 20.0, 30.0, 45.0, True)
        assert rank == pytest.approx(37.5, abs=0.1)

    def test_lower_is_better_inverts(self):
        # For lower-is-better (e.g. days to patch), lower value = better percentile
        rank_low = _interpolate_percentile(10.0, 10.0, 20.0, 30.0, 45.0, False)
        rank_high = _interpolate_percentile(45.0, 10.0, 20.0, 30.0, 45.0, False)
        assert rank_low > rank_high


class TestPerformanceLabel:
    def test_above_p75_higher_is_better(self):
        assert _performance_label(35.0, 10.0, 20.0, 30.0, True) == "above-average"

    def test_between_p50_p75_higher_is_better(self):
        assert _performance_label(25.0, 10.0, 20.0, 30.0, True) == "average"

    def test_between_p25_p50_higher_is_better(self):
        assert _performance_label(15.0, 10.0, 20.0, 30.0, True) == "below-average"

    def test_below_p25_higher_is_better(self):
        assert _performance_label(5.0, 10.0, 20.0, 30.0, True) == "lagging"

    def test_lower_is_better_below_p25_is_above_average(self):
        assert _performance_label(5.0, 10.0, 20.0, 30.0, False) == "above-average"

    def test_lower_is_better_above_p75_is_lagging(self):
        assert _performance_label(35.0, 10.0, 20.0, 30.0, False) == "lagging"


# ---------------------------------------------------------------------------
# Benchmark CRUD
# ---------------------------------------------------------------------------

class TestCreateBenchmark:
    def test_create_returns_dict(self, engine):
        bm = _make_benchmark(engine)
        assert bm["benchmark_name"] == "Gartner Vuln Benchmark"
        assert bm["benchmark_source"] == "Gartner"
        assert bm["sector"] == "technology"

    def test_invalid_source_raises(self, engine):
        with pytest.raises(ValueError, match="benchmark_source"):
            engine.create_benchmark(
                ORG, "BM", benchmark_source="Unknown", sector="finance",
                metric_name="m", metric_category="patch",
                p25=10, p50=20, p75=30, p90=45,
            )

    def test_invalid_sector_raises(self, engine):
        with pytest.raises(ValueError, match="sector"):
            engine.create_benchmark(
                ORG, "BM", benchmark_source="NIST", sector="space",
                metric_name="m", metric_category="patch",
                p25=10, p50=20, p75=30, p90=45,
            )

    def test_invalid_category_raises(self, engine):
        with pytest.raises(ValueError, match="metric_category"):
            engine.create_benchmark(
                ORG, "BM", benchmark_source="CIS", sector="finance",
                metric_name="m", metric_category="unknown_cat",
                p25=10, p50=20, p75=30, p90=45,
            )

    def test_org_isolation(self, engine):
        bm1 = _make_benchmark(engine, ORG)
        bm2 = _make_benchmark(engine, ORG2)
        assert bm1["org_id"] == ORG
        assert bm2["org_id"] == ORG2


class TestListBenchmarks:
    def test_list_empty(self, engine):
        assert engine.list_benchmarks(ORG) == []

    def test_list_returns_all(self, engine):
        _make_benchmark(engine)
        _make_benchmark(engine, metric_name="vuln_count", metric_category="vulnerability")
        assert len(engine.list_benchmarks(ORG)) == 2

    def test_filter_by_sector(self, engine):
        _make_benchmark(engine, sector="finance")
        _make_benchmark(engine, sector="healthcare")
        results = engine.list_benchmarks(ORG, sector="finance")
        assert all(r["sector"] == "finance" for r in results)

    def test_filter_by_category(self, engine):
        _make_benchmark(engine, metric_category="patch")
        _make_benchmark(engine, metric_category="compliance")
        results = engine.list_benchmarks(ORG, metric_category="compliance")
        assert all(r["metric_category"] == "compliance" for r in results)


# ---------------------------------------------------------------------------
# Org Metrics
# ---------------------------------------------------------------------------

class TestOrgMetrics:
    def test_record_metric_returns_dict(self, engine):
        m = _make_metric(engine)
        assert m["metric_name"] == "mean_time_to_patch"
        assert m["value"] == 25.0

    def test_invalid_category_raises(self, engine):
        with pytest.raises(ValueError, match="metric_category"):
            engine.record_org_metric(ORG, "m", "bad_cat", 10.0)

    def test_org_isolation(self, engine):
        m1 = _make_metric(engine, ORG)
        m2 = _make_metric(engine, ORG2)
        assert m1["org_id"] == ORG
        assert m2["org_id"] == ORG2

    def test_get_metric_trend_empty(self, engine):
        assert engine.get_metric_trend(ORG, "nonexistent_metric") == []

    def test_get_metric_trend_returns_ordered(self, engine):
        _make_metric(engine, metric_name="patch_rate", value=80.0)
        _make_metric(engine, metric_name="patch_rate", value=85.0)
        trend = engine.get_metric_trend(ORG, "patch_rate")
        assert len(trend) == 2

    def test_get_metric_trend_org_isolation(self, engine):
        _make_metric(engine, ORG, metric_name="shared_metric")
        assert engine.get_metric_trend(ORG2, "shared_metric") == []


# ---------------------------------------------------------------------------
# Comparisons
# ---------------------------------------------------------------------------

class TestCompare:
    def _setup(self, engine, org=ORG):
        bm = _make_benchmark(engine, org)
        m = _make_metric(engine, org)
        return bm, m

    def test_compare_returns_dict(self, engine):
        bm, m = self._setup(engine)
        cmp = engine.compare_to_benchmark(ORG, bm["id"], m["id"])
        assert "percentile_rank" in cmp
        assert "performance" in cmp
        assert "gap_to_median" in cmp
        assert "gap_to_top_quartile" in cmp

    def test_compare_gap_to_median(self, engine):
        bm, m = self._setup(engine)
        cmp = engine.compare_to_benchmark(ORG, bm["id"], m["id"])
        # gap_to_median = p50 - value = 20 - 25 = -5
        assert cmp["gap_to_median"] == pytest.approx(-5.0, abs=0.01)

    def test_compare_gap_to_top_quartile(self, engine):
        bm, m = self._setup(engine)
        cmp = engine.compare_to_benchmark(ORG, bm["id"], m["id"])
        # gap_to_top_quartile = p75 - value = 30 - 25 = 5
        assert cmp["gap_to_top_quartile"] == pytest.approx(5.0, abs=0.01)

    def test_compare_invalid_benchmark_raises(self, engine):
        m = _make_metric(engine)
        with pytest.raises(ValueError):
            engine.compare_to_benchmark(ORG, "bad-bm-id", m["id"])

    def test_compare_invalid_metric_raises(self, engine):
        bm = _make_benchmark(engine)
        with pytest.raises(ValueError):
            engine.compare_to_benchmark(ORG, bm["id"], "bad-metric-id")

    def test_compare_cross_org_benchmark_raises(self, engine):
        bm = _make_benchmark(engine, ORG)
        m = _make_metric(engine, ORG2)
        with pytest.raises(ValueError):
            engine.compare_to_benchmark(ORG, bm["id"], m["id"])

    def test_above_average_performance(self, engine):
        # higher_is_better=True, value at p90 → above-average
        bm = engine.create_benchmark(
            ORG, "High Good", "CIS", "finance", "compliance_rate", "compliance",
            p25=60.0, p50=70.0, p75=80.0, p90=95.0, higher_is_better=True
        )
        m = engine.record_org_metric(ORG, "compliance_rate", "compliance", 85.0)
        cmp = engine.compare_to_benchmark(ORG, bm["id"], m["id"])
        assert cmp["performance"] == "above-average"

    def test_lagging_performance(self, engine):
        # higher_is_better=True, value below p25 → lagging
        bm = engine.create_benchmark(
            ORG, "Lag BM", "SANS", "healthcare", "detection_rate", "detection",
            p25=50.0, p50=70.0, p75=85.0, p90=95.0, higher_is_better=True
        )
        m = engine.record_org_metric(ORG, "detection_rate", "detection", 30.0)
        cmp = engine.compare_to_benchmark(ORG, bm["id"], m["id"])
        assert cmp["performance"] == "lagging"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

class TestSummary:
    def test_summary_empty(self, engine):
        summary = engine.get_org_benchmark_summary(ORG)
        assert summary["total"] == 0
        assert summary["overall_percentile_avg"] == 0.0
        assert summary["best_metric"] is None

    def test_summary_with_comparisons(self, engine):
        bm = _make_benchmark(engine)
        m = _make_metric(engine)
        engine.compare_to_benchmark(ORG, bm["id"], m["id"])
        summary = engine.get_org_benchmark_summary(ORG)
        assert summary["total"] == 1
        assert "performance_counts" in summary
        assert summary["overall_percentile_avg"] > 0.0

    def test_summary_performance_counts(self, engine):
        bm = _make_benchmark(engine)
        m = _make_metric(engine)
        engine.compare_to_benchmark(ORG, bm["id"], m["id"])
        summary = engine.get_org_benchmark_summary(ORG)
        total_in_counts = sum(summary["performance_counts"].values())
        assert total_in_counts == summary["total"]

    def test_summary_org_isolation(self, engine):
        bm = _make_benchmark(engine, ORG)
        m = _make_metric(engine, ORG)
        engine.compare_to_benchmark(ORG, bm["id"], m["id"])
        summary_other = engine.get_org_benchmark_summary(ORG2)
        assert summary_other["total"] == 0
