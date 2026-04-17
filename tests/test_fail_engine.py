"""Smoke tests for FAILEngine — baseline coverage."""
import pytest

from core.fail_engine import (
    FAILEngine,
    FAILInput,
    FAILResult,
    FAILGrade,
    RecommendedAction,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def engine():
    return FAILEngine()


def _critical_input(**overrides) -> FAILInput:
    defaults = dict(
        cve_id="CVE-2024-3094",
        cvss_score=10.0,
        epss_score=0.97,
        is_kev=True,
        asset_criticality="critical",
        has_exploit=True,
        is_reachable=True,
        data_classification="pii",
    )
    defaults.update(overrides)
    return FAILInput(**defaults)


def _low_input(**overrides) -> FAILInput:
    defaults = dict(
        cve_id="CVE-2024-0001",
        cvss_score=2.0,
        epss_score=0.01,
        is_kev=False,
        asset_criticality="low",
        has_exploit=False,
        is_reachable=False,
        data_classification="public",
    )
    defaults.update(overrides)
    return FAILInput(**defaults)


# ── Instantiation ─────────────────────────────────────────────────────────────

def test_instantiation_default():
    engine = FAILEngine()
    assert engine is not None


def test_instantiation_custom_weights():
    engine = FAILEngine(weights={"fact": 0.3, "assess": 0.2, "impact": 0.3, "likelihood": 0.2})
    assert engine is not None


# ── FAILInput ─────────────────────────────────────────────────────────────────

def test_failinput_creation():
    inp = _critical_input()
    assert inp.cve_id == "CVE-2024-3094"
    assert inp.cvss_score == 10.0


def test_failresult_to_dict():
    """FAILResult (not FAILInput) has to_dict()."""
    engine = FAILEngine()
    result = engine.score(_critical_input())
    d = result.to_dict()
    assert isinstance(d, dict)
    assert "cve_id" in d


# ── score() ───────────────────────────────────────────────────────────────────

def test_score_returns_fail_result(engine):
    result = engine.score(_critical_input())
    assert isinstance(result, FAILResult)


def test_score_critical_has_high_score(engine):
    result = engine.score(_critical_input())
    assert result.fail_score >= 70


def test_score_low_has_lower_score(engine):
    critical = engine.score(_critical_input())
    low = engine.score(_low_input())
    assert critical.fail_score > low.fail_score


def test_score_grade_is_fail_grade(engine):
    result = engine.score(_critical_input())
    assert isinstance(result.grade, FAILGrade)


def test_score_recommended_action_is_enum(engine):
    result = engine.score(_critical_input())
    assert isinstance(result.recommended_action, RecommendedAction)


def test_score_critical_recommends_immediate_patch(engine):
    # Score 84.8 = HIGH (90+ = CRITICAL); HIGH maps to PATCH_NEXT_SPRINT
    result = engine.score(_critical_input())
    assert result.grade in (FAILGrade.HIGH, FAILGrade.CRITICAL)
    assert result.recommended_action in (RecommendedAction.PATCH_IMMEDIATELY, RecommendedAction.PATCH_NEXT_SPRINT)


def test_score_low_recommends_low_priority(engine):
    result = engine.score(_low_input())
    assert result.grade in (FAILGrade.LOW, FAILGrade.INFO)


def test_score_fail_score_range(engine):
    result = engine.score(_critical_input())
    assert 0 <= result.fail_score <= 100


def test_score_stores_history(engine):
    engine.score(_critical_input())
    engine.score(_low_input())
    # history is a property, not a method
    assert len(engine.history) == 2


# ── score_batch() ─────────────────────────────────────────────────────────────

def test_score_batch_returns_list(engine):
    inputs = [_critical_input(), _low_input()]
    results = engine.score_batch(inputs)
    assert isinstance(results, list)
    assert len(results) == 2


def test_score_batch_all_fail_results(engine):
    results = engine.score_batch([_critical_input(), _low_input()])
    assert all(isinstance(r, FAILResult) for r in results)


def test_score_batch_empty(engine):
    results = engine.score_batch([])
    assert results == []


# ── history() ─────────────────────────────────────────────────────────────────

def test_history_empty_on_new_engine():
    # history is a property, not a method; fresh engine has no prior scores
    fresh = FAILEngine()
    assert fresh.history == []


def test_history_grows_with_scores(engine):
    engine.score(_critical_input())
    assert len(engine.history) == 1


# ── stats() ───────────────────────────────────────────────────────────────────

def test_stats_returns_dict(engine):
    engine.score(_critical_input())
    s = engine.stats()
    assert isinstance(s, dict)


def test_stats_empty_engine():
    fresh = FAILEngine()
    s = fresh.stats()
    assert isinstance(s, dict)


# ── compare() ────────────────────────────────────────────────────────────────

def test_compare_returns_dict(engine):
    a = engine.score(_critical_input())
    b = engine.score(_low_input())
    cmp = engine.compare(a, b)
    assert isinstance(cmp, dict)


# ── rank() ───────────────────────────────────────────────────────────────────

def test_rank_orders_by_score(engine):
    a = engine.score(_critical_input())
    b = engine.score(_low_input())
    ranked = engine.rank([b, a])
    assert ranked[0].fail_score >= ranked[-1].fail_score


def test_rank_empty(engine):
    assert engine.rank([]) == []


# ── Grade enum ───────────────────────────────────────────────────────────────

def test_grade_values_exist():
    assert FAILGrade.CRITICAL
    assert FAILGrade.HIGH
    assert FAILGrade.MEDIUM
    assert FAILGrade.LOW
    assert FAILGrade.INFO


# ── RecommendedAction enum ────────────────────────────────────────────────────

def test_recommended_action_patch_immediately():
    assert RecommendedAction.PATCH_IMMEDIATELY
