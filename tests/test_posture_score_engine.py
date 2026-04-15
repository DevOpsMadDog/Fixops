"""Tests for PostureScoreEngine — Security Posture Score Engine."""

import os
import tempfile
import pytest

from core.posture_score_engine import PostureScoreEngine, _score_to_grade, _COMPONENT_WEIGHTS


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "posture_test.db")
    return PostureScoreEngine(db_path=db)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "posture_init.db")
    eng = PostureScoreEngine(db_path=db)
    assert os.path.exists(db)


def test_init_tables_exist(engine):
    import sqlite3
    with sqlite3.connect(engine.db_path) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "posture_scores" in tables
    assert "score_components" in tables
    assert "score_history" in tables
    assert "benchmarks" in tables


# ---------------------------------------------------------------------------
# 2. Grade calculation
# ---------------------------------------------------------------------------

def test_grade_A():
    assert _score_to_grade(95) == "A"

def test_grade_A_boundary():
    assert _score_to_grade(90) == "A"

def test_grade_B():
    assert _score_to_grade(85) == "B"

def test_grade_B_boundary():
    assert _score_to_grade(80) == "B"

def test_grade_C():
    assert _score_to_grade(75) == "C"

def test_grade_C_boundary():
    assert _score_to_grade(70) == "C"

def test_grade_D():
    assert _score_to_grade(65) == "D"

def test_grade_D_boundary():
    assert _score_to_grade(60) == "D"

def test_grade_F():
    assert _score_to_grade(59) == "F"

def test_grade_F_zero():
    assert _score_to_grade(0) == "F"


# ---------------------------------------------------------------------------
# 3. compute_posture_score
# ---------------------------------------------------------------------------

def test_compute_posture_score_defaults(engine):
    result = engine.compute_posture_score("org1")
    assert "overall_score" in result
    assert "grade" in result
    assert "components" in result
    assert "trend" in result
    assert "computed_at" in result


def test_compute_posture_score_weighted(engine):
    # Set all components to 100 → overall should be 100
    for comp in _COMPONENT_WEIGHTS:
        engine.update_component("org1", comp, 100, "test")
    result = engine.compute_posture_score("org1")
    assert result["overall_score"] == pytest.approx(100.0, abs=0.1)
    assert result["grade"] == "A"


def test_compute_posture_score_zero(engine):
    for comp in _COMPONENT_WEIGHTS:
        engine.update_component("org1", comp, 0, "test")
    result = engine.compute_posture_score("org1")
    assert result["overall_score"] == pytest.approx(0.0, abs=0.1)
    assert result["grade"] == "F"


def test_compute_posture_score_components_present(engine):
    result = engine.compute_posture_score("org1")
    for comp in _COMPONENT_WEIGHTS:
        assert comp in result["components"]


# ---------------------------------------------------------------------------
# 4. save_score / get_current_score
# ---------------------------------------------------------------------------

def test_save_and_get_current_score(engine):
    score_data = engine.compute_posture_score("org1")
    engine.save_score("org1", score_data)
    current = engine.get_current_score("org1")
    assert current["org_id"] == "org1"
    assert "overall_score" in current


def test_get_current_score_not_found(engine):
    result = engine.get_current_score("nonexistent_org")
    assert result == {}


def test_save_score_returns_id(engine):
    score_data = engine.compute_posture_score("org1")
    saved = engine.save_score("org1", score_data)
    assert "id" in saved


# ---------------------------------------------------------------------------
# 5. Score history
# ---------------------------------------------------------------------------

def test_get_score_history_empty(engine):
    history = engine.get_score_history("org1")
    assert history == []


def test_get_score_history_after_save(engine):
    for _ in range(3):
        sd = engine.compute_posture_score("org1")
        engine.save_score("org1", sd)
    history = engine.get_score_history("org1", days=30)
    assert len(history) == 3


def test_get_score_history_components_decoded(engine):
    sd = engine.compute_posture_score("org1")
    engine.save_score("org1", sd)
    history = engine.get_score_history("org1")
    assert isinstance(history[0]["components"], dict)


# ---------------------------------------------------------------------------
# 6. update_component / list_components
# ---------------------------------------------------------------------------

def test_update_component_valid(engine):
    ok = engine.update_component("org1", "vulnerability_mgmt_score", 75, "scanner")
    assert ok is True


def test_update_component_invalid(engine):
    ok = engine.update_component("org1", "nonexistent_component", 75, "scanner")
    assert ok is False


def test_update_component_clamped(engine):
    engine.update_component("org1", "training_score", 150, "manual")
    comps = engine.list_components("org1")
    training = next(c for c in comps if c["component"] == "training_score")
    assert training["score"] == 100


def test_list_components_all_present(engine):
    comps = engine.list_components("org1")
    names = {c["component"] for c in comps}
    assert names == set(_COMPONENT_WEIGHTS.keys())


def test_list_components_has_weight(engine):
    comps = engine.list_components("org1")
    for c in comps:
        assert "weight" in c


# ---------------------------------------------------------------------------
# 7. Benchmarks
# ---------------------------------------------------------------------------

def test_add_benchmark(engine):
    result = engine.add_benchmark("org1", {
        "industry": "finance",
        "company_size": "large",
        "avg_score": 72.5,
        "percentile_rank": 65,
        "source": "Gartner",
        "as_of_date": "2026-01-01",
    })
    assert "benchmark_id" in result
    assert result["industry"] == "finance"


def test_list_benchmarks_empty(engine):
    assert engine.list_benchmarks("org1") == []


def test_list_benchmarks_after_add(engine):
    engine.add_benchmark("org1", {"industry": "tech", "avg_score": 68.0, "percentile_rank": 55})
    benchmarks = engine.list_benchmarks("org1")
    assert len(benchmarks) == 1


# ---------------------------------------------------------------------------
# 8. Posture stats
# ---------------------------------------------------------------------------

def test_get_posture_stats_structure(engine):
    sd = engine.compute_posture_score("org1")
    engine.save_score("org1", sd)
    stats = engine.get_posture_stats("org1")
    assert "current_score" in stats
    assert "grade" in stats
    assert "best_score_30d" in stats
    assert "worst_score_30d" in stats
    assert "trend" in stats
    assert "days_at_risk" in stats


def test_get_posture_stats_days_at_risk(engine):
    # Score below 60 → should count as at-risk day
    for comp in _COMPONENT_WEIGHTS:
        engine.update_component("org1", comp, 20, "test")
    sd = engine.compute_posture_score("org1")
    engine.save_score("org1", sd)
    stats = engine.get_posture_stats("org1")
    assert stats["days_at_risk"] >= 1


# ---------------------------------------------------------------------------
# 9. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_scores(engine):
    sd1 = engine.compute_posture_score("org_a")
    engine.update_component("org_a", "training_score", 90, "test")
    engine.save_score("org_a", sd1)

    current_b = engine.get_current_score("org_b")
    assert current_b == {}


def test_org_isolation_benchmarks(engine):
    engine.add_benchmark("org_a", {"industry": "health", "avg_score": 60.0, "percentile_rank": 40})
    assert engine.list_benchmarks("org_b") == []


def test_org_isolation_history(engine):
    sd = engine.compute_posture_score("org_a")
    engine.save_score("org_a", sd)
    assert engine.get_score_history("org_b") == []
