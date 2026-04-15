"""Tests for SecurityCultureEngine — Beast Mode wave 34."""

from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.security_culture_engine import SecurityCultureEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityCultureEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# record_metric
# ---------------------------------------------------------------------------

def test_record_metric_basic(engine):
    m = engine.record_metric(
        org_id="org1",
        metric_name="phishing_click_rate",
        metric_category="phishing-resilience",
        value=5.2,
        target_value=3.0,
        department="Engineering",
        source="phishing-sim",
    )
    assert m["id"]
    assert m["metric_name"] == "phishing_click_rate"
    assert m["value"] == 5.2
    assert m["target_value"] == 3.0
    assert m["department"] == "Engineering"


def test_record_metric_all_categories(engine):
    categories = [
        "phishing-resilience", "training", "policy-compliance",
        "reporting", "champions", "awareness", "incident-response",
    ]
    for i, cat in enumerate(categories):
        m = engine.record_metric("org1", f"metric_{i}", cat, 50.0, 75.0)
        assert m["metric_category"] == cat


def test_record_metric_invalid_category(engine):
    with pytest.raises(ValueError, match="Invalid metric_category"):
        engine.record_metric("org1", "bad", "unknown-category", 10.0, 20.0)


def test_record_metric_no_department(engine):
    m = engine.record_metric("org1", "training_completion", "training", 80.0, 90.0)
    assert m["department"] == ""


def test_record_metric_org_isolation(engine):
    engine.record_metric("org1", "click_rate", "phishing-resilience", 5.0, 3.0, "Eng")
    engine.record_metric("org2", "click_rate", "phishing-resilience", 8.0, 3.0, "Ops")
    trend1 = engine.get_metric_trend("org1", "click_rate")
    trend2 = engine.get_metric_trend("org2", "click_rate")
    assert len(trend1["data_points"]) == 1
    assert len(trend2["data_points"]) == 1
    assert trend1["data_points"][0]["value"] == 5.0
    assert trend2["data_points"][0]["value"] == 8.0


# ---------------------------------------------------------------------------
# get_metric_trend
# ---------------------------------------------------------------------------

def test_get_metric_trend_empty(engine):
    result = engine.get_metric_trend("org1", "nonexistent")
    assert result["trend"] == "stable"
    assert result["data_points"] == []


def test_get_metric_trend_single_point(engine):
    engine.record_metric("org1", "awareness", "awareness", 60.0, 80.0)
    result = engine.get_metric_trend("org1", "awareness")
    assert result["trend"] == "stable"
    assert len(result["data_points"]) == 1


def test_get_metric_trend_improving(engine):
    # Insert directly to control timestamps
    import sqlite3
    conn = sqlite3.connect(engine._db_path)
    import uuid
    for i, val in enumerate([40.0, 45.0, 50.0, 60.0, 70.0, 80.0]):
        conn.execute(
            """INSERT INTO culture_metrics
               (id, org_id, metric_name, metric_category, value, target_value,
                department, measurement_date, source, created_at)
               VALUES (?, 'org1', 'training_score', 'training', ?, 90.0, '', ?, '', ?)""",
            (str(uuid.uuid4()), val, f"2026-01-{i+1:02d}T00:00:00+00:00", f"2026-01-{i+1:02d}T00:00:00+00:00"),
        )
    conn.commit()
    conn.close()
    result = engine.get_metric_trend("org1", "training_score")
    assert result["trend"] == "improving"


def test_get_metric_trend_declining(engine):
    import sqlite3, uuid
    conn = sqlite3.connect(engine._db_path)
    for i, val in enumerate([80.0, 75.0, 65.0, 50.0, 40.0, 30.0]):
        conn.execute(
            """INSERT INTO culture_metrics
               (id, org_id, metric_name, metric_category, value, target_value,
                department, measurement_date, source, created_at)
               VALUES (?, 'org1', 'policy_compliance', 'policy-compliance', ?, 80.0, '', ?, '', ?)""",
            (str(uuid.uuid4()), val, f"2026-01-{i+1:02d}T00:00:00+00:00", f"2026-01-{i+1:02d}T00:00:00+00:00"),
        )
    conn.commit()
    conn.close()
    result = engine.get_metric_trend("org1", "policy_compliance")
    assert result["trend"] == "declining"


def test_get_metric_trend_filter_department(engine):
    engine.record_metric("org1", "click_rate", "phishing-resilience", 5.0, 3.0, "Engineering")
    engine.record_metric("org1", "click_rate", "phishing-resilience", 8.0, 3.0, "Sales")
    result = engine.get_metric_trend("org1", "click_rate", department="Engineering")
    assert len(result["data_points"]) == 1
    assert result["data_points"][0]["department"] == "Engineering"


# ---------------------------------------------------------------------------
# create_initiative
# ---------------------------------------------------------------------------

def test_create_initiative_basic(engine):
    init = engine.create_initiative(
        org_id="org1",
        initiative_name="Security Awareness Campaign Q1",
        initiative_type="campaign",
        target_audience="all-staff",
        start_date="2026-01-01",
        end_date="2026-03-31",
    )
    assert init["id"]
    assert init["status"] == "planned"
    assert init["participants"] == 0
    assert init["completion_rate"] == 0.0
    assert init["impact_score"] == 0.0


def test_create_initiative_all_types(engine):
    types = [
        "training", "campaign", "gamification", "champions-program",
        "simulation", "workshop", "communication",
    ]
    for i, t in enumerate(types):
        init = engine.create_initiative("org1", f"Initiative {i}", t, "all", "2026-01-01", "2026-12-31")
        assert init["initiative_type"] == t


def test_create_initiative_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid initiative_type"):
        engine.create_initiative("org1", "Bad", "hackathon", "all", "2026-01-01", "2026-12-31")


# ---------------------------------------------------------------------------
# update_initiative_progress
# ---------------------------------------------------------------------------

def test_update_initiative_progress_basic(engine):
    init = engine.create_initiative("org1", "Test", "training", "all", "2026-01-01", "2026-12-31")
    updated = engine.update_initiative_progress(init["id"], "org1", 50, 40.0, 6.5)
    assert updated["participants"] == 50
    assert updated["completion_rate"] == 40.0
    assert updated["impact_score"] == 6.5
    assert updated["status"] == "in-progress"


def test_update_initiative_progress_completed(engine):
    init = engine.create_initiative("org1", "Test2", "campaign", "all", "2026-01-01", "2026-12-31")
    updated = engine.update_initiative_progress(init["id"], "org1", 100, 100.0, 8.0)
    assert updated["status"] == "completed"


def test_update_initiative_impact_score_clamped_high(engine):
    init = engine.create_initiative("org1", "Test3", "workshop", "all", "2026-01-01", "2026-12-31")
    updated = engine.update_initiative_progress(init["id"], "org1", 10, 50.0, 15.0)
    assert updated["impact_score"] == 10.0


def test_update_initiative_impact_score_clamped_low(engine):
    init = engine.create_initiative("org1", "Test4", "simulation", "all", "2026-01-01", "2026-12-31")
    updated = engine.update_initiative_progress(init["id"], "org1", 10, 50.0, -5.0)
    assert updated["impact_score"] == 0.0


def test_update_initiative_not_found(engine):
    with pytest.raises(KeyError):
        engine.update_initiative_progress("bad-id", "org1", 10, 50.0, 5.0)


def test_update_initiative_wrong_org(engine):
    init = engine.create_initiative("org1", "Test5", "training", "all", "2026-01-01", "2026-12-31")
    with pytest.raises(KeyError):
        engine.update_initiative_progress(init["id"], "org2", 10, 50.0, 5.0)


def test_update_initiative_overdue_past_end_date(engine):
    init = engine.create_initiative("org1", "OldCampaign", "campaign", "all", "2025-01-01", "2025-06-30")
    updated = engine.update_initiative_progress(init["id"], "org1", 50, 50.0, 5.0)
    # Past end_date and not completed → overdue
    assert updated["status"] == "overdue"


# ---------------------------------------------------------------------------
# create_assessment
# ---------------------------------------------------------------------------

def test_create_assessment_basic(engine):
    a = engine.create_assessment(
        org_id="org1",
        overall_score=75.0,
        strengths=["Good training completion"],
        weaknesses=["Low phishing resilience"],
        recommendations=["Run monthly simulations"],
        assessed_by="CISO",
    )
    assert a["id"]
    assert a["overall_score"] == 75.0
    assert a["maturity_level"] == "managed"
    assert isinstance(a["strengths"], list)
    assert isinstance(a["weaknesses"], list)
    assert isinstance(a["recommendations"], list)


def test_create_assessment_maturity_optimized(engine):
    a = engine.create_assessment("org1", 80.0, [], [], [], "CISO")
    assert a["maturity_level"] == "optimized"


def test_create_assessment_maturity_optimized_exact(engine):
    a = engine.create_assessment("org1", 80.0, [], [], [], "CISO")
    assert a["maturity_level"] == "optimized"


def test_create_assessment_maturity_managed(engine):
    a = engine.create_assessment("org1", 60.0, [], [], [], "CISO")
    assert a["maturity_level"] == "managed"


def test_create_assessment_maturity_defined(engine):
    a = engine.create_assessment("org1", 40.0, [], [], [], "CISO")
    assert a["maturity_level"] == "defined"


def test_create_assessment_maturity_developing(engine):
    a = engine.create_assessment("org1", 20.0, [], [], [], "CISO")
    assert a["maturity_level"] == "developing"


def test_create_assessment_maturity_initial(engine):
    a = engine.create_assessment("org1", 10.0, [], [], [], "CISO")
    assert a["maturity_level"] == "initial"


def test_create_assessment_score_clamped_high(engine):
    a = engine.create_assessment("org1", 150.0, [], [], [], "CISO")
    assert a["overall_score"] == 100.0


def test_create_assessment_score_clamped_low(engine):
    a = engine.create_assessment("org1", -10.0, [], [], [], "CISO")
    assert a["overall_score"] == 0.0
    assert a["maturity_level"] == "initial"


# ---------------------------------------------------------------------------
# get_latest_assessment
# ---------------------------------------------------------------------------

def test_get_latest_assessment_none(engine):
    assert engine.get_latest_assessment("org1") is None


def test_get_latest_assessment_returns_most_recent(engine):
    engine.create_assessment("org1", 50.0, ["s1"], ["w1"], ["r1"], "analyst")
    engine.create_assessment("org1", 70.0, ["s2"], ["w2"], ["r2"], "CISO")
    latest = engine.get_latest_assessment("org1")
    assert latest["overall_score"] == 70.0


def test_get_latest_assessment_parsed_lists(engine):
    engine.create_assessment(
        "org1", 65.0,
        ["strength A", "strength B"],
        ["weakness X"],
        ["rec 1", "rec 2", "rec 3"],
        "CISO",
    )
    latest = engine.get_latest_assessment("org1")
    assert len(latest["strengths"]) == 2
    assert len(latest["weaknesses"]) == 1
    assert len(latest["recommendations"]) == 3


# ---------------------------------------------------------------------------
# get_department_culture_scores
# ---------------------------------------------------------------------------

def test_get_department_culture_scores_empty(engine):
    result = engine.get_department_culture_scores("org1")
    assert result["departments"] == {}
    assert result["best_department"] is None
    assert result["worst_department"] is None


def test_get_department_culture_scores_populated(engine):
    engine.record_metric("org1", "click_rate", "phishing-resilience", 90.0, 80.0, "Engineering")
    engine.record_metric("org1", "click_rate", "phishing-resilience", 80.0, 80.0, "Engineering")
    engine.record_metric("org1", "click_rate", "phishing-resilience", 50.0, 80.0, "Sales")

    result = engine.get_department_culture_scores("org1")
    assert "Engineering" in result["departments"]
    assert "Sales" in result["departments"]
    assert result["best_department"] == "Engineering"
    assert result["worst_department"] == "Sales"


def test_get_department_culture_scores_skips_no_dept(engine):
    engine.record_metric("org1", "awareness", "awareness", 60.0, 80.0, "")
    engine.record_metric("org1", "training", "training", 70.0, 80.0, "Finance")
    result = engine.get_department_culture_scores("org1")
    assert "" not in result["departments"]
    assert "Finance" in result["departments"]


# ---------------------------------------------------------------------------
# get_culture_summary
# ---------------------------------------------------------------------------

def test_get_culture_summary_empty(engine):
    summary = engine.get_culture_summary("org1")
    assert summary["latest_score"] is None
    assert summary["maturity_level"] is None
    assert summary["active_initiatives"] == 0
    assert summary["metrics_above_target"] == 0
    assert summary["metrics_below_target"] == 0
    assert summary["culture_trend"] == "stable"


def test_get_culture_summary_with_data(engine):
    engine.create_assessment("org1", 72.0, [], [], [], "CISO")
    init = engine.create_initiative("org1", "Campaign", "campaign", "all", "2026-01-01", "2026-12-31")
    engine.update_initiative_progress(init["id"], "org1", 50, 50.0, 5.0)
    engine.record_metric("org1", "training", "training", 85.0, 80.0)  # above target (85 >= 80)
    engine.record_metric("org1", "click_rate", "phishing-resilience", 2.0, 3.0)  # below target (2 < 3)

    summary = engine.get_culture_summary("org1")
    assert summary["latest_score"] == 72.0
    assert summary["maturity_level"] == "managed"
    assert summary["active_initiatives"] == 1
    assert summary["metrics_above_target"] == 1
    assert summary["metrics_below_target"] == 1


def test_get_culture_summary_trend_improving(engine):
    engine.create_assessment("org1", 50.0, [], [], [], "analyst")
    engine.create_assessment("org1", 75.0, [], [], [], "CISO")
    summary = engine.get_culture_summary("org1")
    assert summary["culture_trend"] == "improving"


def test_get_culture_summary_trend_declining(engine):
    engine.create_assessment("org1", 80.0, [], [], [], "CISO")
    engine.create_assessment("org1", 55.0, [], [], [], "analyst")
    summary = engine.get_culture_summary("org1")
    assert summary["culture_trend"] == "declining"
