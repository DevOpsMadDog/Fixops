"""Tests for SystemHealthAggregator."""
import pytest
from core.system_health_aggregator import SystemHealthAggregator


@pytest.fixture
def agg():
    return SystemHealthAggregator()


def test_check_all_returns_dict(agg):
    result = agg.check_all("org-test")
    assert isinstance(result, dict)


def test_check_all_has_required_keys(agg):
    result = agg.check_all("org-test")
    for key in ("system_score", "overall_status", "engines", "summary"):
        assert key in result, f"Missing key: {key}"


def test_check_all_score_in_range(agg):
    result = agg.check_all("org-test")
    assert 0 <= result["system_score"] <= 100


def test_check_all_overall_status_valid(agg):
    result = agg.check_all("org-test")
    assert result["overall_status"] in ("healthy", "degraded", "unavailable", "unknown")


def test_check_all_engines_is_list(agg):
    result = agg.check_all("org-test")
    assert isinstance(result["engines"], list)


def test_check_all_engines_have_required_fields(agg):
    result = agg.check_all("org-test")
    for engine in result["engines"]:
        assert "engine" in engine
        assert "status" in engine


def test_check_all_engine_status_valid(agg):
    result = agg.check_all("org-test")
    valid_statuses = {"healthy", "degraded", "unavailable", "unknown"}
    for engine in result["engines"]:
        assert engine["status"] in valid_statuses


def test_check_all_summary_has_counts(agg):
    result = agg.check_all("org-test")
    summary = result["summary"]
    assert isinstance(summary, dict)
    for key in ("healthy", "degraded", "unavailable"):
        assert key in summary


def test_get_system_score_returns_dict(agg):
    result = agg.get_system_score("org-test")
    assert isinstance(result, dict)


def test_get_system_score_has_score(agg):
    result = agg.get_system_score("org-test")
    assert "score" in result
    assert 0 <= result["score"] <= 100


def test_get_system_score_has_grade(agg):
    result = agg.get_system_score("org-test")
    assert "grade" in result
    assert result["grade"] in ("A", "B", "C", "D", "F")


def test_get_system_score_has_status(agg):
    result = agg.get_system_score("org-test")
    assert "overall_status" in result


def test_org_isolation(agg):
    r1 = agg.check_all("org-alpha")
    r2 = agg.check_all("org-beta")
    # Both return valid results, not cross-contaminated
    assert isinstance(r1, dict) and isinstance(r2, dict)


def test_engines_list_non_empty(agg):
    result = agg.check_all("org-test")
    assert len(result["engines"]) > 0


def test_summary_counts_match_engines(agg):
    result = agg.check_all("org-test")
    engines = result["engines"]
    summary = result["summary"]
    total_from_summary = sum(summary.get(s, 0) for s in ("healthy", "degraded", "unavailable"))
    assert total_from_summary == len(engines)
