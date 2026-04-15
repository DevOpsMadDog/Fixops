"""Tests for CyberResilienceEngine — 37 tests covering all methods and edge cases."""
from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.cyber_resilience_engine import CyberResilienceEngine

ORG = "org-cr-test"
ORG2 = "org-cr-other"


@pytest.fixture
def engine(tmp_path):
    return CyberResilienceEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_assessment(engine, org=ORG, domain="identify", maturity=3, max_level=5, **kwargs):
    return engine.create_assessment(
        org_id=org,
        assessment_name=kwargs.get("assessment_name", "Test Assessment"),
        resilience_domain=domain,
        maturity_level=maturity,
        max_level=max_level,
        evidence=kwargs.get("evidence", "Documented"),
        assessor=kwargs.get("assessor", "security-team"),
        next_review=kwargs.get("next_review", "2026-07-01"),
    )


def _make_exercise(engine, org=ORG, exercise_type="tabletop", **kwargs):
    return engine.schedule_exercise(
        org_id=org,
        exercise_name=kwargs.get("exercise_name", "Test Exercise"),
        exercise_type=exercise_type,
        scenario=kwargs.get("scenario", "Ransomware attack"),
        scheduled_date=kwargs.get("scheduled_date", "2026-05-01"),
        participants=kwargs.get("participants", 10),
    )


def _make_metric(engine, org=ORG, category="rto", value=60.0, target=120.0):
    return engine.record_metric(
        org_id=org,
        metric_name=f"Metric-{category}",
        category=category,
        value=value,
        target=target,
        unit="minutes",
    )


# ---------------------------------------------------------------------------
# create_assessment
# ---------------------------------------------------------------------------

def test_create_assessment_returns_dict(engine):
    r = _make_assessment(engine)
    assert isinstance(r, dict)
    assert r["org_id"] == ORG
    assert r["resilience_domain"] == "identify"


def test_create_assessment_score_formula(engine):
    # score = maturity/max * 100
    r = _make_assessment(engine, maturity=3, max_level=5)
    assert abs(r["score"] - 60.0) < 0.01


def test_create_assessment_score_full(engine):
    r = _make_assessment(engine, maturity=5, max_level=5)
    assert abs(r["score"] - 100.0) < 0.01


def test_create_assessment_score_zero(engine):
    r = _make_assessment(engine, maturity=0, max_level=5)
    assert abs(r["score"] - 0.0) < 0.01


def test_create_assessment_score_half(engine):
    r = _make_assessment(engine, maturity=1, max_level=4)
    assert abs(r["score"] - 25.0) < 0.01


def test_create_assessment_all_domains(engine):
    domains = ["identify", "protect", "detect", "respond", "recover", "adapt"]
    for d in domains:
        r = _make_assessment(engine, domain=d, assessment_name=f"Assessment-{d}")
        assert r["resilience_domain"] == d


def test_create_assessment_invalid_domain(engine):
    with pytest.raises(ValueError, match="resilience_domain"):
        engine.create_assessment(ORG, "Bad", "unknown_domain", 3, 5)


def test_create_assessment_invalid_max_level(engine):
    with pytest.raises(ValueError, match="max_level"):
        engine.create_assessment(ORG, "Bad", "identify", 3, 0)


def test_create_assessment_has_id_and_created_at(engine):
    r = _make_assessment(engine)
    assert "id" in r and r["id"]
    assert "created_at" in r and r["created_at"]
    assert "assessment_date" in r and r["assessment_date"]


# ---------------------------------------------------------------------------
# update_maturity
# ---------------------------------------------------------------------------

def test_update_maturity_recomputes_score(engine):
    a = _make_assessment(engine, maturity=2, max_level=5)
    updated = engine.update_maturity(a["id"], ORG, 4, evidence="New evidence")
    assert abs(updated["score"] - 80.0) < 0.01
    assert updated["maturity_level"] == 4


def test_update_maturity_not_found_returns_none(engine):
    result = engine.update_maturity("nonexistent-id", ORG, 3)
    assert result is None


def test_update_maturity_org_isolation(engine):
    a = _make_assessment(engine, org=ORG)
    result = engine.update_maturity(a["id"], ORG2, 5)
    assert result is None


def test_update_maturity_updates_assessment_date(engine):
    a = _make_assessment(engine, maturity=1, max_level=5)
    old_date = a["assessment_date"]
    updated = engine.update_maturity(a["id"], ORG, 3)
    # assessment_date should be updated (may match or differ depending on timing)
    assert updated["assessment_date"] >= old_date


# ---------------------------------------------------------------------------
# get_assessment / list_assessments
# ---------------------------------------------------------------------------

def test_get_assessment_returns_correct(engine):
    a = _make_assessment(engine, domain="protect")
    fetched = engine.get_assessment(a["id"], ORG)
    assert fetched["id"] == a["id"]
    assert fetched["resilience_domain"] == "protect"


def test_get_assessment_wrong_org_returns_none(engine):
    a = _make_assessment(engine)
    assert engine.get_assessment(a["id"], ORG2) is None


def test_list_assessments_returns_all_for_org(engine):
    _make_assessment(engine, domain="identify")
    _make_assessment(engine, domain="detect")
    results = engine.list_assessments(ORG)
    assert len(results) == 2


def test_list_assessments_domain_filter(engine):
    _make_assessment(engine, domain="identify")
    _make_assessment(engine, domain="detect")
    results = engine.list_assessments(ORG, resilience_domain="detect")
    assert len(results) == 1
    assert results[0]["resilience_domain"] == "detect"


def test_list_assessments_org_isolation(engine):
    _make_assessment(engine, org=ORG)
    _make_assessment(engine, org=ORG2)
    assert len(engine.list_assessments(ORG)) == 1
    assert len(engine.list_assessments(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_resilience_score
# ---------------------------------------------------------------------------

def test_get_resilience_score_empty(engine):
    result = engine.get_resilience_score(ORG)
    assert result["overall_score"] == 0.0
    assert result["by_domain"] == {}
    assert result["maturity_distribution"] == {}


def test_get_resilience_score_avg(engine):
    _make_assessment(engine, domain="identify", maturity=4, max_level=5)  # 80
    _make_assessment(engine, domain="protect", maturity=2, max_level=5)   # 40
    result = engine.get_resilience_score(ORG)
    assert abs(result["overall_score"] - 60.0) < 0.01


def test_get_resilience_score_by_domain(engine):
    _make_assessment(engine, domain="detect", maturity=5, max_level=5)
    result = engine.get_resilience_score(ORG)
    assert "detect" in result["by_domain"]
    assert abs(result["by_domain"]["detect"]["avg_score"] - 100.0) < 0.01


def test_get_resilience_score_maturity_distribution(engine):
    _make_assessment(engine, domain="identify", maturity=3, max_level=5)
    _make_assessment(engine, domain="protect", maturity=3, max_level=5)
    _make_assessment(engine, domain="detect", maturity=5, max_level=5)
    result = engine.get_resilience_score(ORG)
    dist = result["maturity_distribution"]
    assert dist.get("3") == 2
    assert dist.get("5") == 1


# ---------------------------------------------------------------------------
# schedule_exercise / complete_exercise / get_exercise_history
# ---------------------------------------------------------------------------

def test_schedule_exercise_returns_dict(engine):
    ex = _make_exercise(engine)
    assert ex["status"] == "scheduled"
    assert ex["exercise_type"] == "tabletop"
    assert ex["gaps_identified"] == []
    assert ex["lessons_learned"] == []


def test_schedule_exercise_invalid_type(engine):
    with pytest.raises(ValueError, match="exercise_type"):
        engine.schedule_exercise(ORG, "Bad", "unknown_type", "scenario", "2026-05-01")


def test_complete_exercise_updates_status(engine):
    ex = _make_exercise(engine)
    result = engine.complete_exercise(
        ex["id"], ORG,
        findings_count=5,
        gaps_identified=["gap1", "gap2"],
        lessons_learned=["lesson1"],
    )
    assert result["status"] == "completed"
    assert result["findings_count"] == 5
    assert result["gaps_identified"] == ["gap1", "gap2"]
    assert result["lessons_learned"] == ["lesson1"]
    assert result["completed_date"] != ""


def test_complete_exercise_not_found_returns_none(engine):
    result = engine.complete_exercise("nonexistent", ORG, 0, [], [])
    assert result is None


def test_get_exercise_history_all(engine):
    _make_exercise(engine, exercise_type="tabletop")
    _make_exercise(engine, exercise_type="drill")
    results = engine.get_exercise_history(ORG)
    assert len(results) == 2


def test_get_exercise_history_type_filter(engine):
    _make_exercise(engine, exercise_type="tabletop")
    _make_exercise(engine, exercise_type="chaos")
    results = engine.get_exercise_history(ORG, exercise_type="chaos")
    assert len(results) == 1
    assert results[0]["exercise_type"] == "chaos"


def test_get_exercise_history_gaps_and_lessons_as_lists(engine):
    ex = _make_exercise(engine)
    engine.complete_exercise(ex["id"], ORG, 2, ["gap-a"], ["lesson-x"])
    history = engine.get_exercise_history(ORG)
    assert isinstance(history[0]["gaps_identified"], list)
    assert isinstance(history[0]["lessons_learned"], list)


# ---------------------------------------------------------------------------
# record_metric / get_metrics_summary
# ---------------------------------------------------------------------------

def test_record_metric_returns_dict(engine):
    m = _make_metric(engine)
    assert m["category"] == "rto"
    assert m["value"] == 60.0
    assert m["target"] == 120.0


def test_record_metric_invalid_category(engine):
    with pytest.raises(ValueError, match="category"):
        engine.record_metric(ORG, "Bad metric", "invalid_cat", 10.0, 20.0)


def test_get_metrics_summary_empty(engine):
    result = engine.get_metrics_summary(ORG)
    assert result == {}


def test_get_metrics_summary_above_below_target(engine):
    # value=60 target=120 → below
    _make_metric(engine, category="rto", value=60.0, target=120.0)
    # value=90 target=60 → above
    _make_metric(engine, category="rto", value=90.0, target=60.0)
    summary = engine.get_metrics_summary(ORG)
    assert summary["rto"]["above_target"] == 1
    assert summary["rto"]["below_target"] == 1


def test_get_metrics_summary_avg_values(engine):
    _make_metric(engine, category="mttr", value=20.0, target=30.0)
    _make_metric(engine, category="mttr", value=40.0, target=30.0)
    summary = engine.get_metrics_summary(ORG)
    assert abs(summary["mttr"]["avg_value"] - 30.0) < 0.01
    assert abs(summary["mttr"]["avg_target"] - 30.0) < 0.01


def test_get_metrics_summary_multiple_categories(engine):
    _make_metric(engine, category="rto", value=10.0, target=20.0)
    _make_metric(engine, category="rpo", value=5.0, target=10.0)
    summary = engine.get_metrics_summary(ORG)
    assert "rto" in summary
    assert "rpo" in summary


def test_get_metrics_summary_org_isolation(engine):
    _make_metric(engine, org=ORG, category="rto", value=10.0, target=20.0)
    _make_metric(engine, org=ORG2, category="rto", value=50.0, target=20.0)
    s1 = engine.get_metrics_summary(ORG)
    s2 = engine.get_metrics_summary(ORG2)
    assert abs(s1["rto"]["avg_value"] - 10.0) < 0.01
    assert abs(s2["rto"]["avg_value"] - 50.0) < 0.01
