"""Tests for the Security Posture Improvement Advisor.

22+ tests covering analysis, recommendations lifecycle, roadmap, and stats.
"""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, "suite-core")

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from core.posture_advisor import PostureAdvisor


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

POOR_POSTURE = {
    "posture_score": 30.0,
    "open_critical_vulns": 5,
    "avg_patch_time_days": 60.0,
    "mfa_coverage_pct": 60.0,
    "avg_mttd_hours": 8.0,
    "unencrypted_databases": 2,
    "wildcard_permissions_count": 3,
    "sla_compliance_pct": 70.0,
}

GOOD_POSTURE = {
    "posture_score": 90.0,
    "open_critical_vulns": 0,
    "avg_patch_time_days": 5.0,
    "mfa_coverage_pct": 100.0,
    "avg_mttd_hours": 0.5,
    "unencrypted_databases": 0,
    "wildcard_permissions_count": 0,
    "sla_compliance_pct": 99.0,
}


@pytest.fixture
def advisor(tmp_path):
    """PostureAdvisor using an isolated temp DB."""
    db_file = str(tmp_path / "test_posture_advisor.db")
    return PostureAdvisor(db_path=db_file)


@pytest.fixture
def poor_analysis(advisor):
    """Pre-run analysis with poor posture data."""
    return advisor.analyze_posture(POOR_POSTURE, org_id="test-org")


# ---------------------------------------------------------------------------
# analyze_posture
# ---------------------------------------------------------------------------


def test_analyze_posture_returns_dict(advisor):
    result = advisor.analyze_posture(POOR_POSTURE, org_id="test-org")
    assert isinstance(result, dict)


def test_analyze_posture_has_analysis_id(advisor):
    result = advisor.analyze_posture(POOR_POSTURE, org_id="test-org")
    assert "analysis_id" in result
    assert result["analysis_id"].startswith("ana-")


def test_analyze_posture_has_posture_score(advisor):
    result = advisor.analyze_posture(POOR_POSTURE, org_id="test-org")
    assert result["posture_score"] == 30.0


def test_analyze_posture_poor_has_critical_count(poor_analysis):
    assert poor_analysis["critical_count"] > 0


def test_analyze_posture_poor_has_recommendations(poor_analysis):
    assert poor_analysis["total_recommendations"] > 0


def test_analyze_posture_recommendations_is_list(poor_analysis):
    assert isinstance(poor_analysis["recommendations"], list)
    assert len(poor_analysis["recommendations"]) > 0


def test_analyze_posture_good_fewer_recommendations(advisor):
    poor = advisor.analyze_posture(POOR_POSTURE, org_id="org-a")
    good = advisor.analyze_posture(GOOD_POSTURE, org_id="org-b")
    assert good["total_recommendations"] < poor["total_recommendations"]


def test_analyze_posture_good_zero_critical(advisor):
    result = advisor.analyze_posture(GOOD_POSTURE, org_id="org-good")
    assert result["critical_count"] == 0


def test_each_recommendation_has_priority(poor_analysis):
    for rec in poor_analysis["recommendations"]:
        assert "priority" in rec
        assert rec["priority"] in ("critical", "high", "medium", "low")


def test_each_recommendation_has_category(poor_analysis):
    for rec in poor_analysis["recommendations"]:
        assert "category" in rec
        assert len(rec["category"]) > 0


def test_each_recommendation_has_title(poor_analysis):
    for rec in poor_analysis["recommendations"]:
        assert "title" in rec
        assert len(rec["title"]) > 0


def test_estimated_score_improvement_is_float(poor_analysis):
    val = poor_analysis["estimated_score_improvement"]
    assert isinstance(val, float)
    assert val >= 0.0


def test_recommendations_have_open_status(poor_analysis):
    for rec in poor_analysis["recommendations"]:
        assert rec["status"] == "open"


# ---------------------------------------------------------------------------
# list_recommendations
# ---------------------------------------------------------------------------


def test_list_recommendations_returns_list(advisor, poor_analysis):
    recs = advisor.list_recommendations(org_id="test-org")
    assert isinstance(recs, list)


def test_list_recommendations_non_empty_for_poor_posture(advisor, poor_analysis):
    recs = advisor.list_recommendations(org_id="test-org")
    assert len(recs) > 0


def test_list_recommendations_category_filter(advisor, poor_analysis):
    recs = advisor.list_recommendations(org_id="test-org", category="vulnerability_management")
    for rec in recs:
        assert rec["category"] == "vulnerability_management"


def test_list_recommendations_priority_filter(advisor, poor_analysis):
    recs = advisor.list_recommendations(org_id="test-org", priority="critical")
    for rec in recs:
        assert rec["priority"] == "critical"


def test_list_recommendations_status_filter(advisor, poor_analysis):
    recs = advisor.list_recommendations(org_id="test-org", status="open")
    for rec in recs:
        assert rec["status"] == "open"


# ---------------------------------------------------------------------------
# accept_recommendation
# ---------------------------------------------------------------------------


def test_accept_recommendation_changes_status(advisor, poor_analysis):
    rec_id = poor_analysis["recommendations"][0]["rec_id"]
    result = advisor.accept_recommendation(rec_id, owner="alice", target_date="2026-05-01", org_id="test-org")
    assert result["status"] == "accepted"


def test_accept_recommendation_sets_owner(advisor, poor_analysis):
    rec_id = poor_analysis["recommendations"][0]["rec_id"]
    result = advisor.accept_recommendation(rec_id, owner="bob", target_date="2026-06-01", org_id="test-org")
    assert result["owner"] == "bob"


def test_accept_recommendation_not_found_raises(advisor):
    with pytest.raises(ValueError, match="not found"):
        advisor.accept_recommendation("nonexistent-id", owner="x", target_date="2026-01-01")


# ---------------------------------------------------------------------------
# complete_recommendation
# ---------------------------------------------------------------------------


def test_complete_recommendation_changes_status(advisor, poor_analysis):
    rec_id = poor_analysis["recommendations"][0]["rec_id"]
    advisor.accept_recommendation(rec_id, owner="alice", target_date="2026-05-01")
    result = advisor.complete_recommendation(rec_id, completed_by="alice", actual_improvement=5.0)
    assert result["status"] == "completed"


def test_complete_recommendation_sets_completed_by(advisor, poor_analysis):
    rec_id = poor_analysis["recommendations"][1]["rec_id"] if len(poor_analysis["recommendations"]) > 1 else poor_analysis["recommendations"][0]["rec_id"]
    result = advisor.complete_recommendation(rec_id, completed_by="carol", actual_improvement=3.0)
    assert result["completed_by"] == "carol"


# ---------------------------------------------------------------------------
# dismiss_recommendation
# ---------------------------------------------------------------------------


def test_dismiss_recommendation_changes_status(advisor, poor_analysis):
    rec_id = poor_analysis["recommendations"][-1]["rec_id"]
    result = advisor.dismiss_recommendation(rec_id, reason="Not applicable to our stack", org_id="test-org")
    assert result["status"] == "dismissed"


def test_dismiss_recommendation_stores_reason(advisor, poor_analysis):
    rec_id = poor_analysis["recommendations"][-1]["rec_id"]
    result = advisor.dismiss_recommendation(rec_id, reason="Risk accepted by CISO", org_id="test-org")
    assert result["dismiss_reason"] == "Risk accepted by CISO"


# ---------------------------------------------------------------------------
# get_roadmap
# ---------------------------------------------------------------------------


def test_get_roadmap_returns_dict(advisor, poor_analysis):
    roadmap = advisor.get_roadmap(org_id="test-org")
    assert isinstance(roadmap, dict)


def test_get_roadmap_has_phases(advisor, poor_analysis):
    roadmap = advisor.get_roadmap(org_id="test-org")
    assert "phases" in roadmap
    assert isinstance(roadmap["phases"], list)


def test_get_roadmap_has_three_phases(advisor, poor_analysis):
    roadmap = advisor.get_roadmap(org_id="test-org")
    assert len(roadmap["phases"]) == 3


def test_get_roadmap_phases_have_timeframe(advisor, poor_analysis):
    roadmap = advisor.get_roadmap(org_id="test-org")
    for phase in roadmap["phases"]:
        assert "timeframe" in phase
        assert "phase" in phase
        assert "recommendations" in phase


def test_get_roadmap_has_total_estimated_improvement(advisor, poor_analysis):
    roadmap = advisor.get_roadmap(org_id="test-org")
    assert "total_estimated_improvement" in roadmap
    assert isinstance(roadmap["total_estimated_improvement"], float)


# ---------------------------------------------------------------------------
# get_advisor_stats
# ---------------------------------------------------------------------------


def test_get_advisor_stats_returns_dict(advisor):
    stats = advisor.get_advisor_stats(org_id="test-org")
    assert isinstance(stats, dict)


def test_get_advisor_stats_has_numeric_fields(advisor, poor_analysis):
    stats = advisor.get_advisor_stats(org_id="test-org")
    assert isinstance(stats["total_analyses"], int)
    assert isinstance(stats["recommendations_accepted"], int)
    assert isinstance(stats["recommendations_completed"], int)
    assert isinstance(stats["avg_score_improvement"], float)


def test_recommendations_accepted_count_increments(advisor, poor_analysis):
    stats_before = advisor.get_advisor_stats(org_id="test-org")
    rec_id = poor_analysis["recommendations"][0]["rec_id"]
    advisor.accept_recommendation(rec_id, owner="dave", target_date="2026-07-01", org_id="test-org")
    stats_after = advisor.get_advisor_stats(org_id="test-org")
    assert stats_after["recommendations_accepted"] == stats_before["recommendations_accepted"] + 1


def test_total_analyses_increments(advisor):
    stats_before = advisor.get_advisor_stats(org_id="test-org")
    advisor.analyze_posture(POOR_POSTURE, org_id="test-org")
    stats_after = advisor.get_advisor_stats(org_id="test-org")
    assert stats_after["total_analyses"] == stats_before["total_analyses"] + 1


def test_recommendations_completed_count_increments(advisor, poor_analysis):
    stats_before = advisor.get_advisor_stats(org_id="test-org")
    rec_id = poor_analysis["recommendations"][0]["rec_id"]
    advisor.complete_recommendation(rec_id, completed_by="eve", actual_improvement=4.0)
    stats_after = advisor.get_advisor_stats(org_id="test-org")
    assert stats_after["recommendations_completed"] == stats_before["recommendations_completed"] + 1
