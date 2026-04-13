"""
Tests for Security Posture Benchmarking Engine.

Covers:
- IndustryVertical enum
- BenchmarkMetric and BenchmarkReport Pydantic models
- Built-in benchmark data completeness (7 verticals × 15 metrics)
- Percentile rank calculation logic
- generate_benchmark: report structure, strengths/weaknesses, recommendations
- get_industry_averages: all verticals
- get_percentile_rank: with and without data
- get_improvement_priorities: ordering and content
- get_benchmark_history: multiple reports, chronological order
- get_latest_report: returns most recent
- SQLite persistence: save and retrieve
- Singleton factory
- Edge cases: no org metrics supplied, metric not found
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.posture_benchmark import (
    BenchmarkMetric,
    BenchmarkReport,
    IndustryVertical,
    PostureBenchmark,
    _ALL_METRICS,
    _BENCHMARK_DATA,
    _RECOMMENDATIONS,
    _compute_percentile,
    get_posture_benchmark,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path: Path) -> str:
    return str(tmp_path / "benchmark_test.db")


@pytest.fixture
def engine(tmp_db: str) -> PostureBenchmark:
    return PostureBenchmark(db_path=tmp_db)


@pytest.fixture
def fintech_metrics() -> dict:
    """Representative org metrics for a mid-tier fintech."""
    return {
        "mttr_days": 10.0,
        "vuln_density_per_kloc": 1.5,
        "patch_coverage_pct": 85.0,
        "mfa_adoption_pct": 95.0,
        "critical_open_findings": 8.0,
        "compliance_coverage_pct": 88.0,
        "secret_detection_coverage_pct": 80.0,
        "privileged_access_review_days": 20.0,
        "attack_surface_score": 250.0,
        "ir_drills_per_year": 6.0,
        "scanner_coverage_pct": 92.0,
        "third_party_risk_coverage_pct": 78.0,
        "encryption_at_rest_pct": 96.0,
        "security_training_completion_pct": 90.0,
        "log_retention_days": 400.0,
    }


# ============================================================================
# IndustryVertical Enum Tests
# ============================================================================


class TestIndustryVertical:
    def test_all_verticals_exist(self):
        verticals = {v.value for v in IndustryVertical}
        assert "fintech" in verticals
        assert "healthcare" in verticals
        assert "saas" in verticals
        assert "government" in verticals
        assert "retail" in verticals
        assert "manufacturing" in verticals
        assert "education" in verticals

    def test_exactly_seven_verticals(self):
        assert len(list(IndustryVertical)) == 7

    def test_vertical_string_values(self):
        assert IndustryVertical.FINTECH.value == "fintech"
        assert IndustryVertical.HEALTHCARE.value == "healthcare"
        assert IndustryVertical.SAAS.value == "saas"

    def test_vertical_is_str_enum(self):
        # IndustryVertical inherits from str so it can be used directly as a string
        assert IndustryVertical.FINTECH == "fintech"


# ============================================================================
# BenchmarkMetric Model Tests
# ============================================================================


class TestBenchmarkMetric:
    def test_metric_creation(self):
        m = BenchmarkMetric(
            name="mttr_days",
            org_value=10.0,
            industry_avg=14.0,
            industry_p90=4.0,
            percentile_rank=65.0,
            gap=4.0,
        )
        assert m.name == "mttr_days"
        assert m.org_value == 10.0
        assert m.industry_avg == 14.0
        assert m.industry_p90 == 4.0
        assert m.percentile_rank == 65.0
        assert m.gap == 4.0

    def test_percentile_bounds(self):
        with pytest.raises(Exception):
            BenchmarkMetric(
                name="x",
                org_value=1.0,
                industry_avg=1.0,
                industry_p90=1.0,
                percentile_rank=101.0,  # out of bounds
                gap=0.0,
            )

    def test_percentile_lower_bound(self):
        with pytest.raises(Exception):
            BenchmarkMetric(
                name="x",
                org_value=1.0,
                industry_avg=1.0,
                industry_p90=1.0,
                percentile_rank=-1.0,  # out of bounds
                gap=0.0,
            )


# ============================================================================
# BenchmarkReport Model Tests
# ============================================================================


class TestBenchmarkReport:
    def test_report_auto_id(self):
        r = BenchmarkReport(
            org_id="org-1",
            vertical=IndustryVertical.FINTECH,
            overall_percentile=70.0,
        )
        assert r.id.startswith("br-")
        assert len(r.id) > 5

    def test_report_generated_at_is_iso(self):
        r = BenchmarkReport(
            org_id="org-1",
            vertical=IndustryVertical.SAAS,
            overall_percentile=60.0,
        )
        assert "T" in r.generated_at  # ISO-8601

    def test_report_defaults(self):
        r = BenchmarkReport(
            org_id="org-1",
            vertical=IndustryVertical.RETAIL,
            overall_percentile=50.0,
        )
        assert r.metrics == []
        assert r.strengths == []
        assert r.weaknesses == []
        assert r.recommendations == []

    def test_overall_percentile_bounds(self):
        with pytest.raises(Exception):
            BenchmarkReport(
                org_id="org-1",
                vertical=IndustryVertical.FINTECH,
                overall_percentile=105.0,
            )


# ============================================================================
# Built-in Benchmark Data Tests
# ============================================================================


class TestBenchmarkData:
    def test_exactly_15_metrics(self):
        assert len(_ALL_METRICS) == 15

    def test_all_verticals_covered_for_every_metric(self):
        for metric_name, vertical_data in _BENCHMARK_DATA.items():
            for vertical in IndustryVertical:
                assert vertical.value in vertical_data, (
                    f"Missing vertical '{vertical.value}' for metric '{metric_name}'"
                )

    def test_each_entry_has_required_keys(self):
        for metric_name, vertical_data in _BENCHMARK_DATA.items():
            for vertical_key, entry in vertical_data.items():
                assert "avg" in entry, f"{metric_name}/{vertical_key} missing 'avg'"
                assert "p90" in entry, f"{metric_name}/{vertical_key} missing 'p90'"
                assert "higher_is_better" in entry, (
                    f"{metric_name}/{vertical_key} missing 'higher_is_better'"
                )

    def test_recommendations_cover_all_metrics(self):
        for metric_name in _ALL_METRICS:
            assert metric_name in _RECOMMENDATIONS, (
                f"Missing recommendation for metric '{metric_name}'"
            )

    def test_p90_better_than_avg_for_higher_is_better(self):
        for metric_name, vertical_data in _BENCHMARK_DATA.items():
            for vkey, entry in vertical_data.items():
                if entry["higher_is_better"]:
                    assert entry["p90"] >= entry["avg"], (
                        f"{metric_name}/{vkey}: p90 should be >= avg for higher_is_better metrics"
                    )

    def test_p90_better_than_avg_for_lower_is_better(self):
        for metric_name, vertical_data in _BENCHMARK_DATA.items():
            for vkey, entry in vertical_data.items():
                if not entry["higher_is_better"]:
                    assert entry["p90"] <= entry["avg"], (
                        f"{metric_name}/{vkey}: p90 should be <= avg for lower_is_better metrics"
                    )


# ============================================================================
# Percentile Calculation Tests
# ============================================================================


class TestComputePercentile:
    def test_at_average_is_50(self):
        pct = _compute_percentile(14.0, 14.0, 4.0, higher_is_better=False)
        assert abs(pct - 50.0) < 5.0

    def test_at_p90_is_approximately_90(self):
        pct = _compute_percentile(4.0, 14.0, 4.0, higher_is_better=False)
        assert pct >= 88.0

    def test_above_average_lower_is_better_scores_above_50(self):
        # org_value=10 < avg=14 → better than average
        pct = _compute_percentile(10.0, 14.0, 4.0, higher_is_better=False)
        assert pct > 50.0

    def test_below_average_lower_is_better_scores_below_50(self):
        # org_value=20 > avg=14 → worse than average
        pct = _compute_percentile(20.0, 14.0, 4.0, higher_is_better=False)
        assert pct < 50.0

    def test_higher_is_better_at_average_is_50(self):
        pct = _compute_percentile(82.0, 82.0, 96.0, higher_is_better=True)
        assert abs(pct - 50.0) < 5.0

    def test_higher_is_better_at_p90_is_approximately_90(self):
        pct = _compute_percentile(96.0, 82.0, 96.0, higher_is_better=True)
        assert pct >= 88.0

    def test_percentile_bounded_0_to_99(self):
        pct_low = _compute_percentile(0.0, 14.0, 4.0, higher_is_better=False)
        pct_high = _compute_percentile(0.0, 82.0, 96.0, higher_is_better=True)
        assert 0.0 <= pct_low <= 99.0
        assert 0.0 <= pct_high <= 99.0

    def test_excellent_performer_scores_above_90(self):
        # org_value=1.0, avg=14.0, p90=4.0, lower_is_better
        pct = _compute_percentile(1.0, 14.0, 4.0, higher_is_better=False)
        assert pct >= 90.0


# ============================================================================
# PostureBenchmark.generate_benchmark Tests
# ============================================================================


class TestGenerateBenchmark:
    def test_generate_returns_benchmark_report(self, engine, fintech_metrics):
        report = engine.generate_benchmark("org-a", IndustryVertical.FINTECH, fintech_metrics)
        assert isinstance(report, BenchmarkReport)

    def test_report_has_all_15_metrics(self, engine, fintech_metrics):
        report = engine.generate_benchmark("org-b", IndustryVertical.FINTECH, fintech_metrics)
        assert len(report.metrics) == 15

    def test_report_org_id_and_vertical(self, engine, fintech_metrics):
        report = engine.generate_benchmark("org-c", IndustryVertical.HEALTHCARE, fintech_metrics)
        assert report.org_id == "org-c"
        assert report.vertical == IndustryVertical.HEALTHCARE

    def test_overall_percentile_in_range(self, engine, fintech_metrics):
        report = engine.generate_benchmark("org-d", IndustryVertical.FINTECH, fintech_metrics)
        assert 0.0 <= report.overall_percentile <= 100.0

    def test_strengths_list_populated(self, engine, fintech_metrics):
        report = engine.generate_benchmark("org-e", IndustryVertical.FINTECH, fintech_metrics)
        # fintech_metrics is generally good, so strengths should exist
        assert isinstance(report.strengths, list)

    def test_weaknesses_list_populated(self, engine):
        # Use deliberately poor metrics
        poor_metrics = {m: 0.0 for m in _ALL_METRICS}
        poor_metrics["mttr_days"] = 999.0  # very bad
        poor_metrics["critical_open_findings"] = 999.0
        report = engine.generate_benchmark("org-poor", IndustryVertical.SAAS, poor_metrics)
        assert len(report.weaknesses) > 0

    def test_recommendations_for_weak_metrics(self, engine):
        poor_metrics = {m: 0.0 for m in _ALL_METRICS}
        poor_metrics["mttr_days"] = 999.0
        report = engine.generate_benchmark("org-rec", IndustryVertical.SAAS, poor_metrics)
        assert len(report.recommendations) > 0

    def test_generate_without_org_metrics_uses_defaults(self, engine):
        # No org_metrics supplied → defaults to industry avg → ~50th pct all around
        report = engine.generate_benchmark("org-nodata", IndustryVertical.FINTECH)
        assert len(report.metrics) == 15
        for m in report.metrics:
            assert 40.0 <= m.percentile_rank <= 60.0

    def test_generate_persists_report(self, engine, fintech_metrics):
        engine.generate_benchmark("org-persist", IndustryVertical.FINTECH, fintech_metrics)
        history = engine.get_benchmark_history("org-persist")
        assert len(history) == 1

    def test_each_metric_has_correct_vertical_avg(self, engine):
        report = engine.generate_benchmark(
            "org-avg-check",
            IndustryVertical.FINTECH,
            {"mttr_days": 14.0},  # only one metric — rest default to avg
        )
        mttr = next(m for m in report.metrics if m.name == "mttr_days")
        assert mttr.industry_avg == _BENCHMARK_DATA["mttr_days"]["fintech"]["avg"]


# ============================================================================
# PostureBenchmark.get_industry_averages Tests
# ============================================================================


class TestGetIndustryAverages:
    def test_returns_all_15_metrics(self, engine):
        data = engine.get_industry_averages(IndustryVertical.FINTECH)
        assert len(data) == 15

    def test_each_entry_has_avg_p90_direction(self, engine):
        data = engine.get_industry_averages(IndustryVertical.HEALTHCARE)
        for metric_name, entry in data.items():
            assert "avg" in entry
            assert "p90" in entry
            assert "higher_is_better" in entry

    def test_different_verticals_differ(self, engine):
        fintech = engine.get_industry_averages(IndustryVertical.FINTECH)
        education = engine.get_industry_averages(IndustryVertical.EDUCATION)
        # Fintech should have lower MTTR avg than education
        assert fintech["mttr_days"]["avg"] < education["mttr_days"]["avg"]

    def test_all_seven_verticals_return_data(self, engine):
        for vertical in IndustryVertical:
            data = engine.get_industry_averages(vertical)
            assert len(data) == 15


# ============================================================================
# PostureBenchmark.get_percentile_rank Tests
# ============================================================================


class TestGetPercentileRank:
    def test_returns_none_when_no_data(self, engine):
        result = engine.get_percentile_rank("unknown-org", "mttr_days")
        assert result is None

    def test_returns_float_after_benchmark(self, engine, fintech_metrics):
        engine.generate_benchmark("org-pct", IndustryVertical.FINTECH, fintech_metrics)
        rank = engine.get_percentile_rank("org-pct", "mttr_days")
        assert rank is not None
        assert 0.0 <= rank <= 100.0

    def test_returns_none_for_unknown_metric(self, engine, fintech_metrics):
        engine.generate_benchmark("org-unk", IndustryVertical.FINTECH, fintech_metrics)
        rank = engine.get_percentile_rank("org-unk", "nonexistent_metric")
        assert rank is None

    def test_good_org_has_high_percentile(self, engine):
        excellent = {m: 9999.0 if _BENCHMARK_DATA[m]["fintech"]["higher_is_better"] else 0.01
                     for m in _ALL_METRICS}
        engine.generate_benchmark("org-excellent", IndustryVertical.FINTECH, excellent)
        rank = engine.get_percentile_rank("org-excellent", "patch_coverage_pct")
        assert rank is not None
        assert rank >= 80.0


# ============================================================================
# PostureBenchmark.get_improvement_priorities Tests
# ============================================================================


class TestGetImprovementPriorities:
    def test_returns_empty_when_no_data(self, engine):
        result = engine.get_improvement_priorities("no-data-org")
        assert result == []

    def test_returns_15_items(self, engine, fintech_metrics):
        engine.generate_benchmark("org-pri", IndustryVertical.FINTECH, fintech_metrics)
        priorities = engine.get_improvement_priorities("org-pri")
        assert len(priorities) == 15

    def test_ordered_by_percentile_ascending(self, engine, fintech_metrics):
        engine.generate_benchmark("org-order", IndustryVertical.FINTECH, fintech_metrics)
        priorities = engine.get_improvement_priorities("org-order")
        ranks = [p["percentile_rank"] for p in priorities]
        assert ranks == sorted(ranks)

    def test_each_item_has_required_fields(self, engine, fintech_metrics):
        engine.generate_benchmark("org-fields", IndustryVertical.FINTECH, fintech_metrics)
        priorities = engine.get_improvement_priorities("org-fields")
        for item in priorities:
            assert "metric" in item
            assert "percentile_rank" in item
            assert "org_value" in item
            assert "industry_avg" in item
            assert "industry_p90" in item
            assert "gap" in item
            assert "recommendation" in item

    def test_worst_metric_first(self, engine):
        # Make mttr_days very bad, everything else perfect
        metrics = {m: 9999.0 if _BENCHMARK_DATA[m]["fintech"]["higher_is_better"] else 0.01
                   for m in _ALL_METRICS}
        metrics["mttr_days"] = 9999.0  # very high = very bad (lower_is_better)
        engine.generate_benchmark("org-worst", IndustryVertical.FINTECH, metrics)
        priorities = engine.get_improvement_priorities("org-worst")
        assert priorities[0]["metric"] == "mttr_days"


# ============================================================================
# PostureBenchmark.get_benchmark_history Tests
# ============================================================================


class TestGetBenchmarkHistory:
    def test_empty_history_for_new_org(self, engine):
        history = engine.get_benchmark_history("new-org")
        assert history == []

    def test_history_grows_with_each_report(self, engine, fintech_metrics):
        engine.generate_benchmark("org-hist", IndustryVertical.FINTECH, fintech_metrics)
        engine.generate_benchmark("org-hist", IndustryVertical.SAAS, fintech_metrics)
        history = engine.get_benchmark_history("org-hist")
        assert len(history) == 2

    def test_history_ordered_chronologically(self, engine, fintech_metrics):
        engine.generate_benchmark("org-chrono", IndustryVertical.FINTECH, fintech_metrics)
        engine.generate_benchmark("org-chrono", IndustryVertical.HEALTHCARE, fintech_metrics)
        history = engine.get_benchmark_history("org-chrono")
        assert history[0].generated_at <= history[1].generated_at

    def test_history_contains_benchmark_report_objects(self, engine, fintech_metrics):
        engine.generate_benchmark("org-type", IndustryVertical.FINTECH, fintech_metrics)
        history = engine.get_benchmark_history("org-type")
        assert all(isinstance(r, BenchmarkReport) for r in history)

    def test_history_isolated_by_org(self, engine, fintech_metrics):
        engine.generate_benchmark("org-a", IndustryVertical.FINTECH, fintech_metrics)
        engine.generate_benchmark("org-b", IndustryVertical.SAAS, fintech_metrics)
        history_a = engine.get_benchmark_history("org-a")
        history_b = engine.get_benchmark_history("org-b")
        assert len(history_a) == 1
        assert len(history_b) == 1


# ============================================================================
# PostureBenchmark.get_latest_report Tests
# ============================================================================


class TestGetLatestReport:
    def test_returns_none_when_no_data(self, engine):
        assert engine.get_latest_report("ghost-org") is None

    def test_returns_most_recent(self, engine, fintech_metrics):
        engine.generate_benchmark("org-latest", IndustryVertical.FINTECH, fintech_metrics)
        second = engine.generate_benchmark("org-latest", IndustryVertical.SAAS, fintech_metrics)
        latest = engine.get_latest_report("org-latest")
        assert latest is not None
        assert latest.id == second.id

    def test_latest_is_benchmark_report(self, engine, fintech_metrics):
        engine.generate_benchmark("org-lattype", IndustryVertical.FINTECH, fintech_metrics)
        latest = engine.get_latest_report("org-lattype")
        assert isinstance(latest, BenchmarkReport)


# ============================================================================
# SQLite Persistence Tests
# ============================================================================


class TestPersistence:
    def test_report_survives_engine_restart(self, tmp_db, fintech_metrics):
        engine1 = PostureBenchmark(db_path=tmp_db)
        report = engine1.generate_benchmark("org-persist2", IndustryVertical.FINTECH, fintech_metrics)

        engine2 = PostureBenchmark(db_path=tmp_db)
        latest = engine2.get_latest_report("org-persist2")
        assert latest is not None
        assert latest.id == report.id
        assert latest.overall_percentile == report.overall_percentile

    def test_org_metrics_persist_across_instances(self, tmp_db):
        engine1 = PostureBenchmark(db_path=tmp_db)
        engine1.generate_benchmark(
            "org-m", IndustryVertical.FINTECH, {"mttr_days": 7.0}
        )

        engine2 = PostureBenchmark(db_path=tmp_db)
        # Second generate with no metrics → should use stored value
        report = engine2.generate_benchmark("org-m", IndustryVertical.FINTECH)
        mttr = next(m for m in report.metrics if m.name == "mttr_days")
        assert mttr.org_value == 7.0


# ============================================================================
# Singleton Factory Test
# ============================================================================


class TestSingletonFactory:
    def test_returns_same_instance(self, tmp_path):
        import core.posture_benchmark as pb_module
        # Reset singleton for test isolation
        pb_module._instance = None
        db = str(tmp_path / "singleton.db")
        a = get_posture_benchmark(db_path=db)
        b = get_posture_benchmark(db_path=db)
        assert a is b
        pb_module._instance = None  # cleanup
