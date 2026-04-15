"""Tests for SecurityPostureTrendEngine — 35+ tests."""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.security_posture_trend_engine import SecurityPostureTrendEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityPostureTrendEngine(db_path=str(tmp_path / "test.db"))


ORG = "org-spt-001"


# ---------------------------------------------------------------------------
# record_datapoint
# ---------------------------------------------------------------------------

class TestRecordDatapoint:
    def test_basic_record(self, engine):
        dp = engine.record_datapoint(ORG, "vuln_score", "vulnerability", 72.5, "score")
        assert dp["id"]
        assert dp["metric_name"] == "vuln_score"
        assert dp["value"] == 72.5
        assert dp["metric_category"] == "vulnerability"
        assert dp["unit"] == "score"
        assert dp["org_id"] == ORG

    def test_all_valid_categories(self, engine):
        categories = [
            "vulnerability", "compliance", "identity", "network",
            "endpoint", "cloud", "data", "awareness",
        ]
        for cat in categories:
            dp = engine.record_datapoint(ORG, f"metric_{cat}", cat, 50.0, "score")
            assert dp["metric_category"] == cat

    def test_all_valid_units(self, engine):
        units = ["score", "percentage", "count", "days", "hours"]
        for unit in units:
            dp = engine.record_datapoint(ORG, "m1", "cloud", 10.0, unit)
            assert dp["unit"] == unit

    def test_source_field(self, engine):
        dp = engine.record_datapoint(ORG, "m2", "compliance", 80.0, "percentage", source="scanner_v2")
        assert dp["source"] == "scanner_v2"

    def test_invalid_category_raises(self, engine):
        with pytest.raises(ValueError, match="metric_category"):
            engine.record_datapoint(ORG, "m3", "invalid_cat", 50.0, "score")

    def test_invalid_unit_raises(self, engine):
        with pytest.raises(ValueError, match="unit"):
            engine.record_datapoint(ORG, "m4", "cloud", 50.0, "invalid_unit")

    def test_multiple_datapoints_same_metric(self, engine):
        for v in [60.0, 70.0, 80.0]:
            engine.record_datapoint(ORG, "cvss_avg", "vulnerability", v, "score")
        # Should have 3 datapoints
        dps = engine._get_datapoints_in_period(ORG, "cvss_avg", 1)
        assert len(dps) == 3

    def test_org_isolation(self, engine):
        engine.record_datapoint("org-a", "metric", "cloud", 10.0, "score")
        engine.record_datapoint("org-b", "metric", "cloud", 99.0, "score")
        dps_a = engine._get_datapoints_in_period("org-a", "metric", 1)
        dps_b = engine._get_datapoints_in_period("org-b", "metric", 1)
        assert dps_a[0]["value"] == 10.0
        assert dps_b[0]["value"] == 99.0


# ---------------------------------------------------------------------------
# analyze_trend
# ---------------------------------------------------------------------------

class TestAnalyzeTrend:
    def _seed(self, engine, metric, values, org=ORG):
        for v in values:
            engine.record_datapoint(org, metric, "vulnerability", v, "score")

    def test_improving_trend(self, engine):
        # velocity = change_pct / period_days must be > 0.5
        # start=50, end=100, change_pct=100%, period=1 day → velocity=100
        self._seed(engine, "open_vulns", [50.0, 75.0, 100.0])
        trend = engine.analyze_trend(ORG, "open_vulns", 1)
        assert trend["trend_label"] == "improving"
        assert trend["velocity"] > 0.5

    def test_declining_trend(self, engine):
        # start=100, end=10, change_pct=-90%, period=1 → velocity=-90
        self._seed(engine, "sec_score", [100.0, 50.0, 10.0])
        trend = engine.analyze_trend(ORG, "sec_score", 1)
        assert trend["trend_label"] == "declining"
        assert trend["velocity"] < -0.5

    def test_stable_trend(self, engine):
        # velocity in [-0.5, 0.5]
        # start=100, end=100.4, period=1 → change_pct=0.4%, velocity=0.4
        self._seed(engine, "stable_metric", [100.0, 100.2, 100.4])
        trend = engine.analyze_trend(ORG, "stable_metric", 1)
        assert trend["trend_label"] == "stable"

    def test_velocity_threshold_exactly_0_5_is_stable(self, engine):
        # velocity == 0.5 → stable (not improving, strict >)
        # start=100, end=100.5, period=1 → change_pct=0.5, velocity=0.5
        self._seed(engine, "threshold_metric", [100.0, 100.5])
        trend = engine.analyze_trend(ORG, "threshold_metric", 1)
        assert trend["trend_label"] == "stable"

    def test_velocity_just_above_0_5_is_improving(self, engine):
        # start=100, end=100.51, period=1 → velocity=0.51
        self._seed(engine, "above_threshold", [100.0, 100.51])
        trend = engine.analyze_trend(ORG, "above_threshold", 1)
        assert trend["trend_label"] == "improving"

    def test_confidence_tier_2(self, engine):
        # 2 datapoints → confidence = 0.5
        self._seed(engine, "c2", [50.0, 60.0])
        trend = engine.analyze_trend(ORG, "c2", 1)
        assert trend["confidence"] == 0.5

    def test_confidence_tier_5(self, engine):
        # 5 datapoints → confidence = 0.7
        self._seed(engine, "c5", [10.0, 20.0, 30.0, 40.0, 50.0])
        trend = engine.analyze_trend(ORG, "c5", 1)
        assert trend["confidence"] == 0.7

    def test_confidence_tier_10(self, engine):
        # 10 datapoints → confidence = 0.9
        self._seed(engine, "c10", list(range(10, 110, 10)))
        trend = engine.analyze_trend(ORG, "c10", 1)
        assert trend["confidence"] == 0.9

    def test_insufficient_datapoints_raises(self, engine):
        self._seed(engine, "single", [50.0])
        with pytest.raises(ValueError, match="Insufficient"):
            engine.analyze_trend(ORG, "single", 1)

    def test_change_pct_computed(self, engine):
        self._seed(engine, "pct_metric", [50.0, 75.0])
        trend = engine.analyze_trend(ORG, "pct_metric", 1)
        assert abs(trend["change_pct"] - 50.0) < 0.01  # (75-50)/50 * 100 = 50%

    def test_start_end_values_stored(self, engine):
        self._seed(engine, "sv_metric", [10.0, 50.0, 90.0])
        trend = engine.analyze_trend(ORG, "sv_metric", 1)
        assert trend["start_value"] == 10.0
        assert trend["end_value"] == 90.0

    def test_persisted_in_db(self, engine):
        self._seed(engine, "persisted", [40.0, 80.0])
        t1 = engine.analyze_trend(ORG, "persisted", 1)
        t2 = engine.get_trend(ORG, "persisted")
        assert t2 is not None
        assert t2["id"] == t1["id"]

    def test_zero_start_value_no_division_error(self, engine):
        self._seed(engine, "zero_start", [0.0, 10.0])
        trend = engine.analyze_trend(ORG, "zero_start", 1)
        assert trend["change_pct"] == 0.0


# ---------------------------------------------------------------------------
# get_trend / list_trends
# ---------------------------------------------------------------------------

class TestGetListTrends:
    def _seed_and_analyze(self, engine, metric, values, org=ORG):
        for v in values:
            engine.record_datapoint(org, metric, "compliance", v, "percentage")
        return engine.analyze_trend(org, metric, 1)

    def test_get_trend_returns_latest(self, engine):
        self._seed_and_analyze(engine, "comp_score", [60.0, 80.0])
        self._seed_and_analyze(engine, "comp_score", [80.0, 90.0])
        trend = engine.get_trend(ORG, "comp_score")
        assert trend is not None
        # Latest has end_value 90
        assert trend["end_value"] == 90.0

    def test_get_trend_none_for_unknown(self, engine):
        assert engine.get_trend(ORG, "nonexistent") is None

    def test_list_trends_all(self, engine):
        self._seed_and_analyze(engine, "m_a", [10.0, 50.0])
        self._seed_and_analyze(engine, "m_b", [100.0, 10.0])
        trends = engine.list_trends(ORG)
        names = {t["metric_name"] for t in trends}
        assert "m_a" in names
        assert "m_b" in names

    def test_list_trends_filter_label(self, engine):
        self._seed_and_analyze(engine, "imp_metric", [10.0, 100.0])
        self._seed_and_analyze(engine, "dec_metric", [100.0, 1.0])
        improving = engine.list_trends(ORG, trend_label="improving")
        for t in improving:
            assert t["trend_label"] == "improving"


# ---------------------------------------------------------------------------
# set_target / update_target_progress / get_targets
# ---------------------------------------------------------------------------

class TestTargets:
    def test_set_target_basic(self, engine):
        target = engine.set_target(ORG, "patch_coverage", 95.0, 70.0, "ciso")
        assert target["target_value"] == 95.0
        assert target["current_value"] == 70.0
        assert target["gap"] == pytest.approx(25.0)
        assert target["set_by"] == "ciso"

    def test_set_target_gap_negative_when_above(self, engine):
        # current > target → gap is negative
        target = engine.set_target(ORG, "vuln_count", 10.0, 50.0, "auto")
        assert target["gap"] == pytest.approx(-40.0)

    def test_eta_none_when_no_trend(self, engine):
        # No trend data → velocity=None → eta_days=None
        target = engine.set_target(ORG, "new_metric", 100.0, 50.0, "admin")
        assert target["eta_days"] is None

    def test_eta_computed_from_velocity(self, engine):
        # Seed and analyze to get a velocity
        for v in [50.0, 100.0]:
            engine.record_datapoint(ORG, "eta_metric", "network", v, "score")
        engine.analyze_trend(ORG, "eta_metric", 1)
        # velocity = 100%, gap = 50 → eta = ceil(50/100) = 1
        target = engine.set_target(ORG, "eta_metric", 150.0, 100.0, "admin")
        assert target["eta_days"] is not None
        assert target["eta_days"] >= 1

    def test_eta_none_when_velocity_zero(self, engine):
        for v in [50.0, 50.0]:
            engine.record_datapoint(ORG, "flat_metric", "endpoint", v, "score")
        engine.analyze_trend(ORG, "flat_metric", 1)
        target = engine.set_target(ORG, "flat_metric", 75.0, 50.0, "admin")
        # velocity=0 → eta=None
        assert target["eta_days"] is None

    def test_update_target_progress(self, engine):
        engine.set_target(ORG, "prog_metric", 100.0, 60.0, "admin")
        updated = engine.update_target_progress(ORG, "prog_metric", 80.0)
        assert updated["current_value"] == 80.0
        assert updated["gap"] == pytest.approx(20.0)

    def test_update_target_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.update_target_progress(ORG, "missing_metric", 50.0)

    def test_get_targets_on_track(self, engine):
        # Seed trend so velocity > 0 → eta_days != None → on_track = True (gap > 0)
        for v in [50.0, 80.0]:
            engine.record_datapoint(ORG, "tracked", "identity", v, "score")
        engine.analyze_trend(ORG, "tracked", 1)
        engine.set_target(ORG, "tracked", 100.0, 80.0, "admin")
        targets = engine.get_targets(ORG)
        t = next(x for x in targets if x["metric_name"] == "tracked")
        assert "on_track" in t

    def test_upsert_replaces_target(self, engine):
        engine.set_target(ORG, "upsert_m", 90.0, 60.0, "a")
        engine.set_target(ORG, "upsert_m", 95.0, 65.0, "b")
        targets = engine.get_targets(ORG)
        tlist = [t for t in targets if t["metric_name"] == "upsert_m"]
        assert len(tlist) == 1
        assert tlist[0]["target_value"] == 95.0


# ---------------------------------------------------------------------------
# get_stagnating_metrics
# ---------------------------------------------------------------------------

class TestStagnating:
    def test_stagnating_no_recent_data(self, engine):
        engine.record_datapoint(ORG, "old_metric", "data", 50.0, "score")
        # threshold_days=0 means "within last 0 days" — all are stagnating
        stagnating = engine.get_stagnating_metrics(ORG, threshold_days=0)
        assert "old_metric" in stagnating

    def test_not_stagnating_with_recent_data(self, engine):
        engine.record_datapoint(ORG, "fresh_metric", "awareness", 80.0, "score")
        stagnating = engine.get_stagnating_metrics(ORG, threshold_days=30)
        assert "fresh_metric" not in stagnating

    def test_returns_sorted_list(self, engine):
        for m in ["z_metric", "a_metric", "m_metric"]:
            engine.record_datapoint(ORG, m, "cloud", 50.0, "score")
        stagnating = engine.get_stagnating_metrics(ORG, threshold_days=0)
        assert stagnating == sorted(stagnating)


# ---------------------------------------------------------------------------
# get_posture_velocity_summary
# ---------------------------------------------------------------------------

class TestVelocitySummary:
    def test_empty_org_returns_empty(self, engine):
        result = engine.get_posture_velocity_summary("empty-org")
        assert result["avg_velocity_by_category"] == {}
        assert result["fastest_improving"] is None
        assert result["fastest_declining"] is None

    def test_summary_with_data(self, engine):
        for v in [50.0, 80.0]:
            engine.record_datapoint(ORG, "vsum_m1", "compliance", v, "score")
        engine.analyze_trend(ORG, "vsum_m1", 1)
        result = engine.get_posture_velocity_summary(ORG)
        assert "compliance" in result["avg_velocity_by_category"]
        assert result["fastest_improving"] is not None
        assert result["fastest_declining"] is not None

    def test_fastest_improving_is_highest_velocity(self, engine):
        for metric, values in [
            ("slow_improve", [50.0, 51.0]),
            ("fast_improve", [50.0, 100.0]),
        ]:
            for v in values:
                engine.record_datapoint(ORG, metric, "network", v, "score")
            engine.analyze_trend(ORG, metric, 1)
        result = engine.get_posture_velocity_summary(ORG)
        assert result["fastest_improving"] == "fast_improve"
