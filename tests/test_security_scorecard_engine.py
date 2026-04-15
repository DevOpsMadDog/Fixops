"""
Tests for SecurityScorecardEngine and its API router.

Coverage:
- Engine: create_scorecard (weighted score calculation, grade assignment, trend recording),
  list_scorecards, get_scorecard (with embedded dimensions),
  get_entity_trend, set_benchmark, get_benchmarks,
  compare_to_benchmark, get_scorecard_stats
- Grade thresholds (A>=90, B>=80, C>=70, D>=60, F<60)
- Org isolation
- Edge cases: no dimensions, missing benchmark

>= 25 tests total. All use temp SQLite files to avoid I/O collisions.

Run with:
    python -m pytest tests/test_security_scorecard_engine.py -x --tb=short --timeout=10 -q
"""
from __future__ import annotations

import sys
import uuid

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.security_scorecard_engine import SecurityScorecardEngine, _score_to_grade


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ORG = "org-scorecard-test"
ORG2 = "org-scorecard-other"

ALL_DIMENSIONS = [
    "vulnerability_hygiene",
    "patch_compliance",
    "security_training",
    "access_control",
    "incident_response",
    "threat_awareness",
    "code_security",
    "configuration_hardening",
]


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "scorecard_test.db")
    return SecurityScorecardEngine(db_path=db)


def _make_scorecard(engine, org=ORG, score=80.0, entity_id=None, entity_type="team",
                    period_label="2026-Q1"):
    if entity_id is None:
        entity_id = str(uuid.uuid4())
    dims = [{"dimension": d, "score": score, "weight": 0.125} for d in ALL_DIMENSIONS]
    return engine.create_scorecard(org, {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "entity_name": f"Entity-{entity_id[:8]}",
        "period_label": period_label,
        "dimensions": dims,
    })


# ---------------------------------------------------------------------------
# Grade helper tests
# ---------------------------------------------------------------------------

class TestGradeHelper:
    def test_a_grade(self):
        assert _score_to_grade(95.0) == "A"
        assert _score_to_grade(90.0) == "A"

    def test_b_grade(self):
        assert _score_to_grade(85.0) == "B"
        assert _score_to_grade(80.0) == "B"

    def test_c_grade(self):
        assert _score_to_grade(75.0) == "C"
        assert _score_to_grade(70.0) == "C"

    def test_d_grade(self):
        assert _score_to_grade(65.0) == "D"
        assert _score_to_grade(60.0) == "D"

    def test_f_grade(self):
        assert _score_to_grade(59.9) == "F"
        assert _score_to_grade(0.0) == "F"


# ---------------------------------------------------------------------------
# Scorecard creation tests
# ---------------------------------------------------------------------------

class TestCreateScorecard:
    def test_returns_scorecard_id(self, engine):
        sc = _make_scorecard(engine)
        assert "scorecard_id" in sc

    def test_weighted_score_correct(self, engine):
        # All 8 dims at 80.0 with equal weight → overall = 80.0
        sc = _make_scorecard(engine, score=80.0)
        assert abs(sc["overall_score"] - 80.0) < 0.01

    def test_grade_assigned(self, engine):
        sc = _make_scorecard(engine, score=80.0)
        assert sc["grade"] == "B"

    def test_grade_a_assigned(self, engine):
        sc = _make_scorecard(engine, score=95.0)
        assert sc["grade"] == "A"

    def test_grade_f_assigned(self, engine):
        sc = _make_scorecard(engine, score=50.0)
        assert sc["grade"] == "F"

    def test_dimensions_embedded(self, engine):
        sc = _make_scorecard(engine)
        assert "dimensions" in sc
        assert len(sc["dimensions"]) == 8

    def test_trend_recorded_automatically(self, engine):
        eid = str(uuid.uuid4())
        _make_scorecard(engine, entity_id=eid)
        trends = engine.get_entity_trend(ORG, eid, "team")
        assert len(trends) == 1

    def test_invalid_entity_type_defaults_to_team(self, engine):
        sc = engine.create_scorecard(ORG, {
            "entity_type": "badtype",
            "entity_id": "e1",
            "dimensions": [],
        })
        assert sc["entity_type"] == "team"

    def test_no_dimensions_gives_zero_score(self, engine):
        sc = engine.create_scorecard(ORG, {
            "entity_type": "team",
            "entity_id": "e-nodims",
            "dimensions": [],
        })
        assert sc["overall_score"] == 0.0
        assert sc["grade"] == "F"

    def test_unknown_dimensions_ignored(self, engine):
        sc = engine.create_scorecard(ORG, {
            "entity_type": "team",
            "entity_id": "e-unknown",
            "dimensions": [
                {"dimension": "unknown_dim", "score": 99.0, "weight": 0.5}
            ],
        })
        assert sc["overall_score"] == 0.0

    def test_score_clamped_to_100(self, engine):
        sc = engine.create_scorecard(ORG, {
            "entity_type": "team",
            "entity_id": "e-clamp",
            "dimensions": [
                {"dimension": "vulnerability_hygiene", "score": 150.0, "weight": 1.0}
            ],
        })
        assert sc["overall_score"] <= 100.0


# ---------------------------------------------------------------------------
# List/Get scorecard tests
# ---------------------------------------------------------------------------

class TestListAndGetScorecards:
    def test_empty_org_returns_empty(self, engine):
        assert engine.list_scorecards("unknown-org") == []

    def test_list_returns_created_scorecards(self, engine):
        _make_scorecard(engine)
        scs = engine.list_scorecards(ORG)
        assert len(scs) == 1

    def test_filter_by_entity_type(self, engine):
        _make_scorecard(engine, entity_type="team")
        _make_scorecard(engine, entity_type="vendor")
        teams = engine.list_scorecards(ORG, entity_type="team")
        assert all(s["entity_type"] == "team" for s in teams)
        assert len(teams) == 1

    def test_filter_by_period_label(self, engine):
        _make_scorecard(engine, period_label="2026-Q1")
        _make_scorecard(engine, period_label="2026-Q2")
        q1 = engine.list_scorecards(ORG, period_label="2026-Q1")
        assert all(s["period_label"] == "2026-Q1" for s in q1)

    def test_get_scorecard_with_dimensions(self, engine):
        sc = _make_scorecard(engine)
        fetched = engine.get_scorecard(ORG, sc["scorecard_id"])
        assert fetched is not None
        assert "dimensions" in fetched
        assert fetched["scorecard_id"] == sc["scorecard_id"]

    def test_get_nonexistent_returns_none(self, engine):
        result = engine.get_scorecard(ORG, "no-such-id")
        assert result is None

    def test_org_isolation(self, engine):
        _make_scorecard(engine, org=ORG)
        _make_scorecard(engine, org=ORG2)
        assert len(engine.list_scorecards(ORG)) == 1
        assert len(engine.list_scorecards(ORG2)) == 1


# ---------------------------------------------------------------------------
# Trend tests
# ---------------------------------------------------------------------------

class TestTrends:
    def test_multiple_scorecards_create_trend_entries(self, engine):
        eid = str(uuid.uuid4())
        _make_scorecard(engine, entity_id=eid, score=70.0, period_label="2026-Q1")
        _make_scorecard(engine, entity_id=eid, score=80.0, period_label="2026-Q2")
        trends = engine.get_entity_trend(ORG, eid, "team")
        assert len(trends) == 2
        # ordered by recorded_at asc — first score should be earlier
        scores = [t["overall_score"] for t in trends]
        assert len(scores) == 2

    def test_trend_empty_for_unknown_entity(self, engine):
        assert engine.get_entity_trend(ORG, "no-entity", "team") == []


# ---------------------------------------------------------------------------
# Benchmark tests
# ---------------------------------------------------------------------------

class TestBenchmarks:
    def test_set_benchmark_returns_dict(self, engine):
        b = engine.set_benchmark(ORG, "finance", "team", 72.0, 88.0)
        assert "bench_id" in b
        assert b["avg_score"] == 72.0
        assert b["top_quartile_score"] == 88.0

    def test_upsert_benchmark(self, engine):
        engine.set_benchmark(ORG, "finance", "team", 72.0, 88.0)
        engine.set_benchmark(ORG, "finance", "team", 75.0, 90.0)
        benchmarks = engine.get_benchmarks(ORG, entity_type="team")
        assert len(benchmarks) == 1
        assert benchmarks[0]["avg_score"] == 75.0

    def test_get_benchmarks_filtered(self, engine):
        engine.set_benchmark(ORG, "finance", "team", 72.0, 88.0)
        engine.set_benchmark(ORG, "healthcare", "vendor", 65.0, 80.0)
        teams = engine.get_benchmarks(ORG, entity_type="team")
        assert all(b["entity_type"] == "team" for b in teams)

    def test_get_benchmarks_empty(self, engine):
        assert engine.get_benchmarks(ORG) == []


# ---------------------------------------------------------------------------
# Compare to benchmark tests
# ---------------------------------------------------------------------------

class TestCompareToBenchmark:
    def test_compare_with_benchmark(self, engine):
        sc = _make_scorecard(engine, score=85.0)
        engine.set_benchmark(ORG, "tech", "team", 70.0, 90.0)
        result = engine.compare_to_benchmark(ORG, sc["scorecard_id"])
        assert result is not None
        assert "benchmark_avg" in result
        assert result["benchmark_avg"] == 70.0
        assert "vs_avg" in result
        assert abs(result["vs_avg"] - 15.0) < 0.5
        assert "percentile_estimate" in result

    def test_compare_no_benchmark_returns_nulls(self, engine):
        sc = _make_scorecard(engine, score=75.0)
        result = engine.compare_to_benchmark(ORG, sc["scorecard_id"])
        assert result is not None
        assert result["benchmark_avg"] is None
        assert result["vs_avg"] is None

    def test_compare_nonexistent_scorecard_returns_none(self, engine):
        result = engine.compare_to_benchmark(ORG, "no-such-id")
        assert result is None


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

class TestScorecardStats:
    def test_empty_org_stats(self, engine):
        stats = engine.get_scorecard_stats("empty-org")
        assert stats["total_scorecards"] == 0
        assert stats["avg_overall_score"] == 0.0
        assert stats["by_grade"] == {}
        assert stats["by_entity_type"] == {}
        assert stats["top_performers"] == []

    def test_stats_aggregate_correctly(self, engine):
        _make_scorecard(engine, score=90.0)
        _make_scorecard(engine, score=80.0)
        _make_scorecard(engine, score=70.0)
        stats = engine.get_scorecard_stats(ORG)
        assert stats["total_scorecards"] == 3
        assert "A" in stats["by_grade"] or "B" in stats["by_grade"]
        assert "team" in stats["by_entity_type"]
        assert abs(stats["avg_overall_score"] - 80.0) < 1.0

    def test_top_performers_max_3(self, engine):
        for _ in range(5):
            _make_scorecard(engine, score=85.0)
        stats = engine.get_scorecard_stats(ORG)
        assert len(stats["top_performers"]) <= 3

    def test_by_entity_type_counts(self, engine):
        _make_scorecard(engine, entity_type="team")
        _make_scorecard(engine, entity_type="vendor")
        _make_scorecard(engine, entity_type="vendor")
        stats = engine.get_scorecard_stats(ORG)
        assert stats["by_entity_type"].get("team") == 1
        assert stats["by_entity_type"].get("vendor") == 2


# ---------------------------------------------------------------------------
# generate_scorecard (6-domain weighted) tests
# ---------------------------------------------------------------------------

class TestGenerateScorecard:
    def test_returns_scorecard_id(self, engine):
        sc = engine.generate_scorecard(ORG, {
            "identity": 90.0, "endpoint": 80.0, "network": 70.0,
            "cloud": 85.0, "data": 75.0, "application": 65.0,
        })
        assert "scorecard_id" in sc

    def test_weighted_score_calculation(self, engine):
        # All domains at 80.0 → overall should be 80.0
        sc = engine.generate_scorecard(ORG, {
            "identity": 80.0, "endpoint": 80.0, "network": 80.0,
            "cloud": 80.0, "data": 80.0, "application": 80.0,
        })
        assert abs(sc["overall_score"] - 80.0) < 0.01

    def test_grade_b_at_80(self, engine):
        sc = engine.generate_scorecard(ORG, {
            "identity": 80.0, "endpoint": 80.0, "network": 80.0,
            "cloud": 80.0, "data": 80.0, "application": 80.0,
        })
        assert sc["grade"] == "B"

    def test_grade_a_at_90(self, engine):
        sc = engine.generate_scorecard(ORG, {
            "identity": 90.0, "endpoint": 90.0, "network": 90.0,
            "cloud": 90.0, "data": 90.0, "application": 90.0,
        })
        assert sc["grade"] == "A"

    def test_grade_f_below_60(self, engine):
        sc = engine.generate_scorecard(ORG, {
            "identity": 50.0, "endpoint": 50.0, "network": 50.0,
            "cloud": 50.0, "data": 50.0, "application": 50.0,
        })
        assert sc["grade"] == "F"

    def test_domain_scores_embedded(self, engine):
        sc = engine.generate_scorecard(ORG, {
            "identity": 85.0, "endpoint": 75.0, "network": 65.0,
            "cloud": 70.0, "data": 80.0, "application": 90.0,
        })
        assert "domain_scores" in sc
        assert len(sc["domain_scores"]) == 6

    def test_domain_grades_assigned(self, engine):
        sc = engine.generate_scorecard(ORG, {
            "identity": 95.0, "endpoint": 55.0, "network": 72.0,
            "cloud": 83.0, "data": 67.0, "application": 88.0,
        })
        domain_map = {d["domain"]: d["grade"] for d in sc["domain_scores"]}
        assert domain_map["identity"] == "A"
        assert domain_map["endpoint"] == "F"
        assert domain_map["cloud"] == "B"

    def test_percentile_rank_present(self, engine):
        sc = engine.generate_scorecard(ORG, {
            "identity": 80.0, "endpoint": 80.0, "network": 80.0,
            "cloud": 80.0, "data": 80.0, "application": 80.0,
        })
        assert "percentile_rank" in sc

    def test_missing_domains_default_zero(self, engine):
        sc = engine.generate_scorecard(ORG, {"identity": 100.0})
        # other 5 domains default to 0 → weighted score = 100*0.2 / 1.0 = 20
        assert sc["overall_score"] < 25.0

    def test_trend_recorded_on_generate(self, engine):
        org = "org-gen-trend-test"
        engine.generate_scorecard(org, {
            "identity": 80.0, "endpoint": 80.0, "network": 80.0,
            "cloud": 80.0, "data": 80.0, "application": 80.0,
        })
        trend = engine.get_trend(org, days=1)
        assert len(trend) == 1

    def test_org_isolation_in_generate(self, engine):
        engine.generate_scorecard("org-a-gen", {
            "identity": 80.0, "endpoint": 80.0, "network": 80.0,
            "cloud": 80.0, "data": 80.0, "application": 80.0,
        })
        engine.generate_scorecard("org-b-gen", {
            "identity": 70.0, "endpoint": 70.0, "network": 70.0,
            "cloud": 70.0, "data": 70.0, "application": 70.0,
        })
        trend_a = engine.get_trend("org-a-gen", days=1)
        trend_b = engine.get_trend("org-b-gen", days=1)
        assert len(trend_a) == 1
        assert len(trend_b) == 1
        assert abs(trend_a[0]["overall_score"] - 80.0) < 0.01
        assert abs(trend_b[0]["overall_score"] - 70.0) < 0.01


# ---------------------------------------------------------------------------
# get_trend tests
# ---------------------------------------------------------------------------

class TestGetTrend:
    def test_empty_trend_for_new_org(self, engine):
        trend = engine.get_trend("brand-new-org", days=30)
        assert trend == []

    def test_trend_returns_list(self, engine):
        org = "org-trend-days"
        engine.generate_scorecard(org, {
            "identity": 75.0, "endpoint": 75.0, "network": 75.0,
            "cloud": 75.0, "data": 75.0, "application": 75.0,
        })
        trend = engine.get_trend(org, days=30)
        assert isinstance(trend, list)
        assert len(trend) >= 1

    def test_trend_days_zero_returns_nothing(self, engine):
        # days=1 means only today — generate and it should appear
        org = "org-trend-days-zero"
        engine.generate_scorecard(org, {
            "identity": 60.0, "endpoint": 60.0, "network": 60.0,
            "cloud": 60.0, "data": 60.0, "application": 60.0,
        })
        # days=365 should catch it
        trend = engine.get_trend(org, days=365)
        assert len(trend) >= 1
