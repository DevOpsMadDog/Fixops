"""Tests for SecurityKPITracker.

22+ tests covering: record, validation, current KPIs, trends, benchmarks,
snapshots, scorecard, and targets.
"""
from __future__ import annotations

import sys
import tempfile
import pytest
from pathlib import Path

sys.path.insert(0, "suite-core")

from core.security_kpi_tracker import SecurityKPITracker, KPI_NAMES, INDUSTRY_BENCHMARKS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tracker(tmp_path):
    """Fresh tracker backed by a temp SQLite DB."""
    db = tmp_path / "test_kpi.db"
    return SecurityKPITracker(db_path=str(db))


@pytest.fixture
def populated_tracker(tracker):
    """Tracker with a handful of pre-recorded KPIs."""
    tracker.record_kpi("mttd_hours", 2.5)
    tracker.record_kpi("mttr_hours", 8.0)
    tracker.record_kpi("patch_compliance_pct", 92.0)
    tracker.record_kpi("posture_score", 75.0)
    tracker.record_kpi("false_positive_rate", 10.0)
    tracker.record_kpi("sla_compliance_pct", 88.0)
    return tracker


# ---------------------------------------------------------------------------
# record_kpi
# ---------------------------------------------------------------------------


def test_record_kpi_returns_dict(tracker):
    result = tracker.record_kpi("mttd_hours", 3.0)
    assert isinstance(result, dict)


def test_record_kpi_has_kpi_id(tracker):
    result = tracker.record_kpi("mttr_hours", 12.0)
    assert "kpi_id" in result
    assert result["kpi_id"]


def test_record_kpi_has_expected_fields(tracker):
    result = tracker.record_kpi("posture_score", 70.0)
    assert result["kpi_name"] == "posture_score"
    assert result["value"] == 70.0
    assert "recorded_at" in result
    assert "period" in result


def test_record_kpi_invalid_name_raises_value_error(tracker):
    with pytest.raises(ValueError, match="Unknown KPI"):
        tracker.record_kpi("not_a_real_kpi", 42.0)


def test_record_kpi_period_default_is_daily(tracker):
    result = tracker.record_kpi("vuln_density", 5.0)
    assert result["period"] == "daily"


def test_record_kpi_custom_period(tracker):
    result = tracker.record_kpi("incidents_per_month", 3.0, period="monthly")
    assert result["period"] == "monthly"


def test_record_kpi_with_metadata(tracker):
    result = tracker.record_kpi("open_critical_count", 7.0, metadata={"source": "scanner"})
    assert result["kpi_id"]  # metadata is stored, record still returned


def test_record_kpi_org_id(tracker):
    result = tracker.record_kpi("mttd_hours", 1.0, org_id="acme")
    assert result["kpi_id"]


# ---------------------------------------------------------------------------
# get_current_kpis
# ---------------------------------------------------------------------------


def test_get_current_kpis_returns_dict(tracker):
    result = tracker.get_current_kpis()
    assert isinstance(result, dict)


def test_get_current_kpis_empty_when_no_records(tracker):
    result = tracker.get_current_kpis()
    assert result == {}


def test_get_current_kpis_contains_recorded_kpi(tracker):
    tracker.record_kpi("mttd_hours", 5.0)
    result = tracker.get_current_kpis()
    assert "mttd_hours" in result
    assert result["mttd_hours"]["value"] == 5.0


def test_get_current_kpis_trend_field(tracker):
    tracker.record_kpi("mttr_hours", 8.0)
    result = tracker.get_current_kpis()
    trend = result["mttr_hours"]["trend"]
    assert trend in ("improving", "stable", "degrading")


def test_get_current_kpis_vs_benchmark_field(tracker):
    tracker.record_kpi("patch_compliance_pct", 97.0)
    result = tracker.get_current_kpis()
    status = result["patch_compliance_pct"]["vs_benchmark"]
    assert status in ("good", "average", "poor", "unknown")


def test_get_current_kpis_good_benchmark(tracker):
    # patch_compliance_pct >= 95 is 'good'
    tracker.record_kpi("patch_compliance_pct", 97.0)
    result = tracker.get_current_kpis()
    assert result["patch_compliance_pct"]["vs_benchmark"] == "good"


def test_get_current_kpis_poor_benchmark(tracker):
    # patch_compliance_pct <= 60 is 'poor'
    tracker.record_kpi("patch_compliance_pct", 50.0)
    result = tracker.get_current_kpis()
    assert result["patch_compliance_pct"]["vs_benchmark"] == "poor"


def test_get_current_kpis_org_isolation(tracker):
    tracker.record_kpi("posture_score", 80.0, org_id="org_a")
    tracker.record_kpi("posture_score", 40.0, org_id="org_b")
    a = tracker.get_current_kpis(org_id="org_a")
    b = tracker.get_current_kpis(org_id="org_b")
    assert a["posture_score"]["value"] == 80.0
    assert b["posture_score"]["value"] == 40.0


# ---------------------------------------------------------------------------
# get_kpi_trend
# ---------------------------------------------------------------------------


def test_get_kpi_trend_returns_list(tracker):
    result = tracker.get_kpi_trend("mttd_hours")
    assert isinstance(result, list)


def test_get_kpi_trend_empty_when_no_records(tracker):
    result = tracker.get_kpi_trend("mttd_hours")
    assert result == []


def test_get_kpi_trend_sorted_chronologically(tracker):
    tracker.record_kpi("mttr_hours", 10.0)
    tracker.record_kpi("mttr_hours", 8.0)
    tracker.record_kpi("mttr_hours", 6.0)
    trend = tracker.get_kpi_trend("mttr_hours", days=30)
    dates = [r["recorded_at"] for r in trend]
    assert dates == sorted(dates)


def test_get_kpi_trend_contains_expected_fields(tracker):
    tracker.record_kpi("sla_compliance_pct", 90.0)
    trend = tracker.get_kpi_trend("sla_compliance_pct")
    assert len(trend) >= 1
    assert "value" in trend[0]
    assert "recorded_at" in trend[0]
    assert "period" in trend[0]


# ---------------------------------------------------------------------------
# get_benchmark_comparison
# ---------------------------------------------------------------------------


def test_get_benchmark_comparison_returns_dict(populated_tracker):
    result = populated_tracker.get_benchmark_comparison()
    assert isinstance(result, dict)
    assert "kpis" in result


def test_get_benchmark_comparison_kpis_is_list(populated_tracker):
    result = populated_tracker.get_benchmark_comparison()
    assert isinstance(result["kpis"], list)


def test_get_benchmark_comparison_status_valid(populated_tracker):
    result = populated_tracker.get_benchmark_comparison()
    valid_statuses = {"good", "average", "poor", "unknown"}
    for item in result["kpis"]:
        assert item["status"] in valid_statuses


def test_get_benchmark_comparison_contains_all_kpi_names(populated_tracker):
    result = populated_tracker.get_benchmark_comparison()
    returned_names = {item["kpi_name"] for item in result["kpis"]}
    for name in KPI_NAMES:
        assert name in returned_names


# ---------------------------------------------------------------------------
# record_snapshot / get_snapshots
# ---------------------------------------------------------------------------


def test_record_snapshot_returns_dict(populated_tracker):
    result = populated_tracker.record_snapshot()
    assert isinstance(result, dict)


def test_record_snapshot_has_snapshot_id(populated_tracker):
    result = populated_tracker.record_snapshot()
    assert "snapshot_id" in result
    assert result["snapshot_id"]


def test_record_snapshot_has_taken_at(populated_tracker):
    result = populated_tracker.record_snapshot()
    assert "taken_at" in result


def test_get_snapshots_returns_list(populated_tracker):
    populated_tracker.record_snapshot()
    result = populated_tracker.get_snapshots()
    assert isinstance(result, list)


def test_get_snapshots_contains_snapshot(populated_tracker):
    populated_tracker.record_snapshot()
    result = populated_tracker.get_snapshots()
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# calculate_score_card
# ---------------------------------------------------------------------------


def test_calculate_score_card_returns_dict(populated_tracker):
    result = populated_tracker.calculate_score_card()
    assert isinstance(result, dict)


def test_calculate_score_card_has_overall_grade(populated_tracker):
    result = populated_tracker.calculate_score_card()
    assert "overall_grade" in result


def test_overall_grade_valid_value(populated_tracker):
    result = populated_tracker.calculate_score_card()
    assert result["overall_grade"] in ("A", "B", "C", "D", "F")


def test_calculate_score_card_has_overall_score(populated_tracker):
    result = populated_tracker.calculate_score_card()
    assert "overall_score" in result
    assert 0.0 <= result["overall_score"] <= 100.0


def test_calculate_score_card_by_category(populated_tracker):
    result = populated_tracker.calculate_score_card()
    assert "by_category" in result
    assert isinstance(result["by_category"], dict)


def test_calculate_score_card_top_strengths_is_list(populated_tracker):
    result = populated_tracker.calculate_score_card()
    assert "top_strengths" in result
    assert isinstance(result["top_strengths"], list)


def test_calculate_score_card_top_weaknesses_is_list(populated_tracker):
    result = populated_tracker.calculate_score_card()
    assert "top_weaknesses" in result
    assert isinstance(result["top_weaknesses"], list)


def test_scorecard_empty_tracker(tracker):
    """Scorecard with no data returns a dict with grade."""
    result = tracker.calculate_score_card()
    assert isinstance(result, dict)
    assert "overall_grade" in result


# ---------------------------------------------------------------------------
# set_target / get_targets
# ---------------------------------------------------------------------------


def test_set_target_returns_dict(tracker):
    result = tracker.set_target("mttd_hours", 0.5, "2026-12-31")
    assert isinstance(result, dict)


def test_set_target_has_target_id(tracker):
    result = tracker.set_target("mttr_hours", 4.0, "2026-06-30")
    assert "target_id" in result
    assert result["target_id"]


def test_set_target_invalid_kpi_raises(tracker):
    with pytest.raises(ValueError):
        tracker.set_target("bad_kpi", 10.0, "2026-12-31")


def test_get_targets_returns_list(tracker):
    result = tracker.get_targets()
    assert isinstance(result, list)


def test_get_targets_contains_set_target(tracker):
    tracker.set_target("posture_score", 90.0, "2026-12-31")
    result = tracker.get_targets()
    assert len(result) >= 1
    names = [r["kpi_name"] for r in result]
    assert "posture_score" in names


def test_get_targets_org_isolation(tracker):
    tracker.set_target("mttd_hours", 1.0, "2026-12-31", org_id="org_x")
    result_x = tracker.get_targets(org_id="org_x")
    result_y = tracker.get_targets(org_id="org_y")
    assert len(result_x) == 1
    assert len(result_y) == 0
