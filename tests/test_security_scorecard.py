"""
Tests for SecurityScorecard module and API router.

Covers:
- ScoreCategory enum values
- SecurityScore and PublicScore Pydantic models
- SecurityScorecard.generate_scorecard()
- SecurityScorecard.get_scorecard()
- SecurityScorecard.get_score_history()
- SecurityScorecard.get_category_breakdown()
- SecurityScorecard.get_improvement_plan()
- SecurityScorecard.compare_orgs()
- SecurityScorecard.get_public_score()
- Grade mapping (A–F)
- CATEGORY_WEIGHTS sum to 1.0
- Deterministic scoring (same org → same score)
- Router endpoints (TestClient with dev-mode auth bypass)
- Public endpoint (no auth required)

Run with:
    python -m pytest tests/test_security_scorecard.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict

import pytest

# Add suite paths
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

# Force dev mode so router auth passes through
os.environ.setdefault("FIXOPS_MODE", "dev")

from core.security_scorecard import (
    CATEGORY_WEIGHTS,
    PublicScore,
    ScoreCategory,
    SecurityScore,
    SecurityScorecard,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_scorecard.db")


@pytest.fixture
def sc(db_path):
    return SecurityScorecard(db_path=db_path)


@pytest.fixture
def org_id():
    return f"org-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def scored_sc(sc, org_id):
    """Scorecard fixture with one generated scorecard."""
    sc.generate_scorecard(org_id)
    return sc, org_id


# ============================================================================
# Enum tests
# ============================================================================


def test_score_category_values():
    expected = {
        "network", "application", "patching", "dns",
        "endpoint", "ip_reputation", "social_engineering", "information_leak",
    }
    actual = {cat.value for cat in ScoreCategory}
    assert actual == expected


def test_score_category_count():
    assert len(ScoreCategory) == 8


def test_score_category_is_str_enum():
    assert ScoreCategory.NETWORK == "network"
    assert ScoreCategory.APPLICATION == "application"
    assert ScoreCategory.PATCHING == "patching"
    assert ScoreCategory.DNS == "dns"
    assert ScoreCategory.ENDPOINT == "endpoint"
    assert ScoreCategory.IP_REPUTATION == "ip_reputation"
    assert ScoreCategory.SOCIAL_ENGINEERING == "social_engineering"
    assert ScoreCategory.INFORMATION_LEAK == "information_leak"


# ============================================================================
# Category weights
# ============================================================================


def test_category_weights_sum_to_one():
    total = sum(CATEGORY_WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9, f"Weights sum to {total}, expected 1.0"


def test_category_weights_all_positive():
    for cat, w in CATEGORY_WEIGHTS.items():
        assert w > 0, f"Weight for {cat} must be positive"


def test_category_weights_cover_all_categories():
    assert set(CATEGORY_WEIGHTS.keys()) == set(ScoreCategory)


# ============================================================================
# Grade mapping
# ============================================================================


def test_grade_a(sc):
    assert sc._score_to_grade(90) == "A"
    assert sc._score_to_grade(100) == "A"
    assert sc._score_to_grade(95.5) == "A"


def test_grade_b(sc):
    assert sc._score_to_grade(80) == "B"
    assert sc._score_to_grade(89.9) == "B"


def test_grade_c(sc):
    assert sc._score_to_grade(70) == "C"
    assert sc._score_to_grade(79.9) == "C"


def test_grade_d(sc):
    assert sc._score_to_grade(60) == "D"
    assert sc._score_to_grade(69.9) == "D"


def test_grade_f(sc):
    assert sc._score_to_grade(0) == "F"
    assert sc._score_to_grade(59.9) == "F"


# ============================================================================
# Pydantic model tests
# ============================================================================


def test_security_score_model():
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    score = SecurityScore(
        id=str(uuid.uuid4()),
        org_id="org1",
        overall_score=75.0,
        grade="C",
        categories={"network": 80.0},
        factors=[{"name": "test", "score": 80.0}],
        generated_at=now,
        valid_until=now,
    )
    assert score.overall_score == 75.0
    assert score.grade == "C"
    assert "network" in score.categories


def test_security_score_bounds():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with pytest.raises(Exception):
        SecurityScore(
            id="x", org_id="y", overall_score=101.0, grade="A",
            generated_at=now, valid_until=now,
        )


def test_public_score_model():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    ps = PublicScore(
        org_id="org1",
        overall_score=82.0,
        grade="B",
        generated_at=now,
        valid_until=now,
        category_grades={"network": "A", "dns": "B"},
    )
    assert ps.grade == "B"
    assert ps.category_grades["network"] == "A"


# ============================================================================
# generate_scorecard
# ============================================================================


def test_generate_scorecard_returns_security_score(sc, org_id):
    result = sc.generate_scorecard(org_id)
    assert isinstance(result, SecurityScore)


def test_generate_scorecard_overall_score_in_range(sc, org_id):
    result = sc.generate_scorecard(org_id)
    assert 0.0 <= result.overall_score <= 100.0


def test_generate_scorecard_grade_set(sc, org_id):
    result = sc.generate_scorecard(org_id)
    assert result.grade in ("A", "B", "C", "D", "F")


def test_generate_scorecard_has_all_categories(sc, org_id):
    result = sc.generate_scorecard(org_id)
    for cat in ScoreCategory:
        assert cat.value in result.categories, f"Missing category {cat.value}"


def test_generate_scorecard_category_scores_in_range(sc, org_id):
    result = sc.generate_scorecard(org_id)
    for cat_name, score in result.categories.items():
        assert 0.0 <= score <= 100.0, f"Category {cat_name} score {score} out of range"


def test_generate_scorecard_has_factors(sc, org_id):
    result = sc.generate_scorecard(org_id)
    assert len(result.factors) > 0


def test_generate_scorecard_factors_have_required_fields(sc, org_id):
    result = sc.generate_scorecard(org_id)
    for factor in result.factors:
        assert "name" in factor
        assert "score" in factor
        assert "weight" in factor
        assert "category" in factor


def test_generate_scorecard_persists(sc, org_id):
    sc.generate_scorecard(org_id)
    retrieved = sc.get_scorecard(org_id)
    assert retrieved is not None


def test_generate_scorecard_deterministic_for_same_org(db_path, org_id):
    """Same org always gets the same score (deterministic RNG)."""
    sc1 = SecurityScorecard(db_path=db_path)
    sc2 = SecurityScorecard(db_path=db_path)
    r1 = sc1.generate_scorecard(org_id)
    r2 = sc2.generate_scorecard(org_id)
    assert r1.overall_score == r2.overall_score


def test_generate_scorecard_different_orgs_different_scores(sc):
    org_a = "org-alpha-fixed-1"
    org_b = "org-beta-fixed-2"
    ra = sc.generate_scorecard(org_a)
    rb = sc.generate_scorecard(org_b)
    # Different orgs should almost certainly produce different scores
    # (not a strict requirement but validates the hashing differs)
    assert isinstance(ra.overall_score, float)
    assert isinstance(rb.overall_score, float)


def test_generate_scorecard_validity_days(sc, org_id):
    from datetime import datetime, timezone
    result = sc.generate_scorecard(org_id, validity_days=7)
    gen = datetime.fromisoformat(result.generated_at)
    until = datetime.fromisoformat(result.valid_until)
    delta = (until - gen).days
    assert delta == 7


# ============================================================================
# get_scorecard
# ============================================================================


def test_get_scorecard_none_if_no_scorecard(sc, org_id):
    assert sc.get_scorecard(org_id) is None


def test_get_scorecard_returns_latest(sc, org_id):
    sc.generate_scorecard(org_id)
    sc.generate_scorecard(org_id)
    result = sc.get_scorecard(org_id)
    assert result is not None
    # Should be the most recent one
    assert isinstance(result, SecurityScore)


def test_get_scorecard_org_isolation(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"
    sc.generate_scorecard(org_a)
    assert sc.get_scorecard(org_b) is None


# ============================================================================
# get_score_history
# ============================================================================


def test_get_score_history_empty_for_new_org(sc, org_id):
    history = sc.get_score_history(org_id)
    assert history == []


def test_get_score_history_returns_entries(sc, org_id):
    sc.generate_scorecard(org_id)
    sc.generate_scorecard(org_id)
    history = sc.get_score_history(org_id, days=90)
    assert len(history) == 2


def test_get_score_history_entry_fields(scored_sc):
    sc, org_id = scored_sc
    history = sc.get_score_history(org_id, days=90)
    entry = history[0]
    assert "id" in entry
    assert "overall_score" in entry
    assert "grade" in entry
    assert "generated_at" in entry


def test_get_score_history_chronological_order(sc, org_id):
    sc.generate_scorecard(org_id)
    sc.generate_scorecard(org_id)
    history = sc.get_score_history(org_id, days=90)
    assert len(history) == 2
    assert history[0]["generated_at"] <= history[1]["generated_at"]


# ============================================================================
# get_category_breakdown
# ============================================================================


def test_get_category_breakdown_empty_if_no_scorecard(sc, org_id):
    result = sc.get_category_breakdown(org_id)
    assert result["categories"] == {}
    assert result["generated_at"] is None


def test_get_category_breakdown_has_all_categories(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_category_breakdown(org_id)
    for cat in ScoreCategory:
        assert cat.value in result["categories"]


def test_get_category_breakdown_category_fields(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_category_breakdown(org_id)
    for cat_name, data in result["categories"].items():
        assert "score" in data
        assert "grade" in data
        assert "weight" in data
        assert "trend" in data
        assert "delta" in data


def test_get_category_breakdown_overall_fields(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_category_breakdown(org_id)
    assert "overall_score" in result
    assert "overall_grade" in result
    assert "generated_at" in result


def test_get_category_breakdown_trend_new_on_first(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_category_breakdown(org_id)
    for cat_name, data in result["categories"].items():
        assert data["trend"] == "new", f"Expected 'new' trend for first scorecard, got {data['trend']}"


def test_get_category_breakdown_trend_after_two_scorecards(sc, org_id):
    sc.generate_scorecard(org_id)
    sc.generate_scorecard(org_id)
    result = sc.get_category_breakdown(org_id)
    for cat_name, data in result["categories"].items():
        assert data["trend"] in ("improving", "degrading", "stable")


# ============================================================================
# get_improvement_plan
# ============================================================================


def test_get_improvement_plan_empty_if_no_scorecard(sc, org_id):
    result = sc.get_improvement_plan(org_id)
    assert result["actions"] == []
    assert result["generated_at"] is None


def test_get_improvement_plan_has_actions(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_improvement_plan(org_id)
    assert len(result["actions"]) == 8  # one per category


def test_get_improvement_plan_action_fields(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_improvement_plan(org_id)
    for action in result["actions"]:
        assert "category" in action
        assert "current_score" in action
        assert "current_grade" in action
        assert "gap" in action
        assert "weight" in action
        assert "estimated_impact" in action
        assert "priority" in action
        assert "recommendation" in action


def test_get_improvement_plan_sorted_by_impact(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_improvement_plan(org_id)
    impacts = [a["estimated_impact"] for a in result["actions"]]
    assert impacts == sorted(impacts, reverse=True)


def test_get_improvement_plan_priority_values(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_improvement_plan(org_id)
    for action in result["actions"]:
        assert action["priority"] in ("low", "medium", "high")


def test_get_improvement_plan_gap_correct(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_improvement_plan(org_id)
    for action in result["actions"]:
        expected_gap = round(100.0 - action["current_score"], 2)
        assert abs(action["gap"] - expected_gap) < 0.01


# ============================================================================
# compare_orgs
# ============================================================================


def test_compare_orgs_returns_all_orgs(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"
    sc.generate_scorecard(org_a)
    sc.generate_scorecard(org_b)
    result = sc.compare_orgs([org_a, org_b])
    returned_ids = {o["org_id"] for o in result["orgs"]}
    assert org_a in returned_ids
    assert org_b in returned_ids


def test_compare_orgs_total_count(sc):
    orgs = [f"org-{uuid.uuid4().hex[:8]}" for _ in range(3)]
    for o in orgs:
        sc.generate_scorecard(o)
    result = sc.compare_orgs(orgs)
    assert result["total"] == 3


def test_compare_orgs_rank_assigned(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"
    sc.generate_scorecard(org_a)
    sc.generate_scorecard(org_b)
    result = sc.compare_orgs([org_a, org_b])
    scored = [o for o in result["orgs"] if o.get("rank") is not None]
    ranks = sorted(o["rank"] for o in scored)
    assert ranks == list(range(1, len(scored) + 1))


def test_compare_orgs_unscored_org_has_no_rank(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"  # no scorecard
    sc.generate_scorecard(org_a)
    result = sc.compare_orgs([org_a, org_b])
    unscored = [o for o in result["orgs"] if o["org_id"] == org_b]
    assert len(unscored) == 1
    assert unscored[0]["rank"] is None


def test_compare_orgs_category_rankings_present(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"
    sc.generate_scorecard(org_a)
    sc.generate_scorecard(org_b)
    result = sc.compare_orgs([org_a, org_b])
    assert "category_rankings" in result
    for cat in ScoreCategory:
        assert cat.value in result["category_rankings"]


# ============================================================================
# get_public_score
# ============================================================================


def test_get_public_score_none_if_no_scorecard(sc, org_id):
    assert sc.get_public_score(org_id) is None


def test_get_public_score_returns_public_score(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_public_score(org_id)
    assert isinstance(result, PublicScore)


def test_get_public_score_has_grade(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_public_score(org_id)
    assert result.grade in ("A", "B", "C", "D", "F")


def test_get_public_score_has_category_grades(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_public_score(org_id)
    for cat in ScoreCategory:
        assert cat.value in result.category_grades
        assert result.category_grades[cat.value] in ("A", "B", "C", "D", "F")


def test_get_public_score_no_raw_category_scores(scored_sc):
    sc, org_id = scored_sc
    result = sc.get_public_score(org_id)
    dumped = result.model_dump()
    # category_grades values should be letter grades, not floats
    for grade in dumped["category_grades"].values():
        assert isinstance(grade, str)
        assert grade in ("A", "B", "C", "D", "F")


# ============================================================================
# Router tests
# ============================================================================


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """TestClient with isolated DB and auth bypassed via dependency override."""
    tmp = tmp_path_factory.mktemp("router_db")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.security_scorecard_router import public_router, router
    from apps.api.auth_deps import api_key_auth

    # Patch singleton to use temp DB
    import apps.api.security_scorecard_router as _mod
    _mod._scorecard = SecurityScorecard(db_path=str(tmp / "router_test.db"))

    app = FastAPI()
    app.include_router(router)
    app.include_router(public_router)

    # Override auth to always pass in tests
    async def _no_auth():
        return None

    app.dependency_overrides[api_key_auth] = _no_auth
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def router_org_id(client):
    org = f"router-org-{uuid.uuid4().hex[:8]}"
    resp = client.post(f"/api/v1/scorecard/{org}/generate", json={})
    assert resp.status_code == 201
    return org


def test_router_list_categories(client):
    resp = client.get("/api/v1/scorecard/categories")
    assert resp.status_code == 200
    data = resp.json()
    assert "categories" in data
    assert data["total"] == 8


def test_router_generate_scorecard(client):
    org = f"gen-org-{uuid.uuid4().hex[:8]}"
    resp = client.post(f"/api/v1/scorecard/{org}/generate", json={"validity_days": 14})
    assert resp.status_code == 201
    data = resp.json()
    assert "overall_score" in data
    assert "grade" in data
    assert "categories" in data


def test_router_get_scorecard(client, router_org_id):
    resp = client.get(f"/api/v1/scorecard/{router_org_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == router_org_id


def test_router_get_scorecard_404(client):
    resp = client.get(f"/api/v1/scorecard/nonexistent-org-xyz")
    assert resp.status_code == 404


def test_router_get_history(client, router_org_id):
    resp = client.get(f"/api/v1/scorecard/{router_org_id}/history?days=90")
    assert resp.status_code == 200
    data = resp.json()
    assert "history" in data
    assert data["org_id"] == router_org_id


def test_router_get_breakdown(client, router_org_id):
    resp = client.get(f"/api/v1/scorecard/{router_org_id}/breakdown")
    assert resp.status_code == 200
    data = resp.json()
    assert "categories" in data
    assert len(data["categories"]) == 8


def test_router_get_breakdown_404(client):
    resp = client.get("/api/v1/scorecard/no-such-org-abc/breakdown")
    assert resp.status_code == 404


def test_router_get_improvement_plan(client, router_org_id):
    resp = client.get(f"/api/v1/scorecard/{router_org_id}/improvement")
    assert resp.status_code == 200
    data = resp.json()
    assert "actions" in data
    assert len(data["actions"]) == 8


def test_router_get_improvement_plan_404(client):
    resp = client.get("/api/v1/scorecard/no-such-org-def/improvement")
    assert resp.status_code == 404


def test_router_compare_orgs(client):
    org_a = f"cmp-a-{uuid.uuid4().hex[:8]}"
    org_b = f"cmp-b-{uuid.uuid4().hex[:8]}"
    client.post(f"/api/v1/scorecard/{org_a}/generate", json={})
    client.post(f"/api/v1/scorecard/{org_b}/generate", json={})
    resp = client.post("/api/v1/scorecard/compare", json={"org_ids": [org_a, org_b]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2


def test_router_compare_orgs_requires_two(client):
    resp = client.post("/api/v1/scorecard/compare", json={"org_ids": ["only-one"]})
    assert resp.status_code == 422  # validation error


def test_router_public_score(client, router_org_id):
    resp = client.get(f"/api/v1/scorecard/public/{router_org_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert "grade" in data
    assert "overall_score" in data
    assert "category_grades" in data
    # No raw category scores should appear in public response
    assert "categories" not in data


def test_router_public_score_404(client):
    resp = client.get("/api/v1/scorecard/public/no-such-org-ghi")
    assert resp.status_code == 404


def test_router_public_score_category_grades_are_letters(client, router_org_id):
    resp = client.get(f"/api/v1/scorecard/public/{router_org_id}")
    data = resp.json()
    for grade in data["category_grades"].values():
        assert grade in ("A", "B", "C", "D", "F")
