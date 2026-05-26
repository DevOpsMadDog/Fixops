"""
Tests for SecurityScorecard module and API router.

Covers:
- ScoreCategory enum values
- SecurityScore and PublicScore Pydantic models
- SecurityScorecard.generate_scorecard() — now raises NotImplementedError (honest-stub policy)
- SecurityScorecard.get_scorecard()
- SecurityScorecard.get_score_history()
- SecurityScorecard.get_category_breakdown()
- SecurityScorecard.get_improvement_plan()
- SecurityScorecard.compare_orgs()
- SecurityScorecard.get_public_score()
- Grade mapping (A–F)
- CATEGORY_WEIGHTS sum to 1.0
- Router endpoints (TestClient with dev-mode auth bypass)
- Public endpoint (no auth required)

Run with:
    python -m pytest tests/test_security_scorecard.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
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
# Seed helper — bypasses generate_scorecard (NotImplementedError) and INSERTs
# a real row directly into the SQLite DB so read-path tests have real data.
# ============================================================================

def _seed_scorecard(
    sc: SecurityScorecard,
    org_id: str,
    overall_score: float = 75.0,
    generated_at: str | None = None,
    validity_days: int = 30,
) -> SecurityScore:
    """Insert a real SecurityScore row into sc's DB and return the model."""
    now = datetime.now(timezone.utc) if generated_at is None else datetime.fromisoformat(generated_at)
    gen_str = now.isoformat()
    until_str = (now + timedelta(days=validity_days)).isoformat()
    grade = sc._score_to_grade(overall_score)
    row_id = str(uuid.uuid4())

    # Build a minimal but complete categories dict (one score per category)
    categories: Dict[str, float] = {cat.value: overall_score for cat in ScoreCategory}
    factors = [
        {"name": f"{cat.value}_factor", "score": overall_score, "weight": 0.125, "category": cat.value}
        for cat in ScoreCategory
    ]

    with sc._get_conn() as conn:
        conn.execute(
            """INSERT INTO scorecards
               (id, org_id, overall_score, grade, categories, factors, generated_at, valid_until)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row_id,
                org_id,
                overall_score,
                grade,
                json.dumps(categories),
                json.dumps(factors),
                gen_str,
                until_str,
            ),
        )

    return SecurityScore(
        id=row_id,
        org_id=org_id,
        overall_score=overall_score,
        grade=grade,
        categories=categories,
        factors=factors,
        generated_at=gen_str,
        valid_until=until_str,
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
    """Scorecard fixture with one seeded scorecard (via direct DB insert — no generate)."""
    _seed_scorecard(sc, org_id)
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
# generate_scorecard — must raise NotImplementedError (honest-stub policy)
# ============================================================================


def test_generate_scorecard_raises_not_implemented(sc, org_id):
    """generate_scorecard() raises NotImplementedError until scanner connectors are wired."""
    with pytest.raises(NotImplementedError):
        sc.generate_scorecard(org_id)


def test_generate_scorecard_raises_without_env(sc, org_id):
    """Confirm the raise happens regardless of SCORECARD_DATA_SOURCE being absent."""
    env_backup = os.environ.pop("SCORECARD_DATA_SOURCE", None)
    try:
        with pytest.raises(NotImplementedError):
            sc.generate_scorecard(org_id)
    finally:
        if env_backup is not None:
            os.environ["SCORECARD_DATA_SOURCE"] = env_backup


def test_generate_scorecard_raises_even_with_env_set(sc, org_id):
    """Even with SCORECARD_DATA_SOURCE set, real aggregation is not yet implemented."""
    os.environ["SCORECARD_DATA_SOURCE"] = "real"
    try:
        with pytest.raises(NotImplementedError):
            sc.generate_scorecard(org_id)
    finally:
        del os.environ["SCORECARD_DATA_SOURCE"]


def test_generate_scorecard_message_mentions_connectors(sc, org_id):
    """NotImplementedError message references connector configuration."""
    with pytest.raises(NotImplementedError, match="connector"):
        sc.generate_scorecard(org_id)


# ============================================================================
# get_scorecard — read path tested via real seeded rows
# ============================================================================


def test_get_scorecard_none_if_no_scorecard(sc, org_id):
    assert sc.get_scorecard(org_id) is None


def test_get_scorecard_returns_latest(sc, org_id):
    # Seed two rows; get_scorecard should return the most recent
    t1 = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    t2 = datetime.now(timezone.utc).isoformat()
    _seed_scorecard(sc, org_id, overall_score=60.0, generated_at=t1)
    _seed_scorecard(sc, org_id, overall_score=80.0, generated_at=t2)
    result = sc.get_scorecard(org_id)
    assert result is not None
    assert isinstance(result, SecurityScore)
    # Most recent row has score 80.0
    assert abs(result.overall_score - 80.0) < 0.01


def test_get_scorecard_org_isolation(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"
    _seed_scorecard(sc, org_a, overall_score=70.0)
    assert sc.get_scorecard(org_b) is None


# ============================================================================
# get_score_history — read path tested via real seeded rows
# ============================================================================


def test_get_score_history_empty_for_new_org(sc, org_id):
    history = sc.get_score_history(org_id)
    assert history == []


def test_get_score_history_returns_entries(sc, org_id):
    t1 = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    t2 = datetime.now(timezone.utc).isoformat()
    _seed_scorecard(sc, org_id, overall_score=65.0, generated_at=t1)
    _seed_scorecard(sc, org_id, overall_score=75.0, generated_at=t2)
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
    t1 = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    t2 = datetime.now(timezone.utc).isoformat()
    _seed_scorecard(sc, org_id, overall_score=60.0, generated_at=t1)
    _seed_scorecard(sc, org_id, overall_score=80.0, generated_at=t2)
    history = sc.get_score_history(org_id, days=90)
    assert len(history) == 2
    assert history[0]["generated_at"] <= history[1]["generated_at"]


# ============================================================================
# get_category_breakdown — read path tested via real seeded rows
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
    t1 = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    t2 = datetime.now(timezone.utc).isoformat()
    _seed_scorecard(sc, org_id, overall_score=65.0, generated_at=t1)
    _seed_scorecard(sc, org_id, overall_score=75.0, generated_at=t2)
    result = sc.get_category_breakdown(org_id)
    for cat_name, data in result["categories"].items():
        assert data["trend"] in ("improving", "degrading", "stable")


# ============================================================================
# get_improvement_plan — read path tested via real seeded rows
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
# compare_orgs — seeded via direct DB inserts
# ============================================================================


def test_compare_orgs_returns_all_orgs(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"
    _seed_scorecard(sc, org_a, overall_score=80.0)
    _seed_scorecard(sc, org_b, overall_score=70.0)
    result = sc.compare_orgs([org_a, org_b])
    returned_ids = {o["org_id"] for o in result["orgs"]}
    assert org_a in returned_ids
    assert org_b in returned_ids


def test_compare_orgs_total_count(sc):
    orgs = [f"org-{uuid.uuid4().hex[:8]}" for _ in range(3)]
    for o in orgs:
        _seed_scorecard(sc, o, overall_score=75.0)
    result = sc.compare_orgs(orgs)
    assert result["total"] == 3


def test_compare_orgs_rank_assigned(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"
    _seed_scorecard(sc, org_a, overall_score=85.0)
    _seed_scorecard(sc, org_b, overall_score=65.0)
    result = sc.compare_orgs([org_a, org_b])
    scored = [o for o in result["orgs"] if o.get("rank") is not None]
    ranks = sorted(o["rank"] for o in scored)
    assert ranks == list(range(1, len(scored) + 1))


def test_compare_orgs_unscored_org_has_no_rank(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"  # no scorecard
    _seed_scorecard(sc, org_a, overall_score=80.0)
    result = sc.compare_orgs([org_a, org_b])
    unscored = [o for o in result["orgs"] if o["org_id"] == org_b]
    assert len(unscored) == 1
    assert unscored[0]["rank"] is None


def test_compare_orgs_category_rankings_present(sc):
    org_a = f"org-{uuid.uuid4().hex[:8]}"
    org_b = f"org-{uuid.uuid4().hex[:8]}"
    _seed_scorecard(sc, org_a, overall_score=80.0)
    _seed_scorecard(sc, org_b, overall_score=70.0)
    result = sc.compare_orgs([org_a, org_b])
    assert "category_rankings" in result
    for cat in ScoreCategory:
        assert cat.value in result["category_rankings"]


# ============================================================================
# get_public_score — read path tested via real seeded rows
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
    """TestClient with isolated DB, auth bypassed, and raise_server_exceptions=False
    so the global NotImplementedError → 501 handler fires for generate calls."""
    tmp = tmp_path_factory.mktemp("router_db")

    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient
    from apps.api.security_scorecard_router import public_router, router
    from apps.api.auth_deps import api_key_auth

    # Patch singleton to use temp DB
    import apps.api.security_scorecard_router as _mod
    _mod._scorecard = SecurityScorecard(db_path=str(tmp / "router_test.db"))

    app = FastAPI()

    # Wire the same NotImplementedError → 501 handler that app.py registers
    @app.exception_handler(NotImplementedError)
    async def _not_implemented_handler(request, exc):
        return JSONResponse(
            status_code=501,
            content={"status": "not_implemented", "error_category": "not_implemented", "message": str(exc)},
        )

    app.include_router(router)
    app.include_router(public_router)

    # Override auth to always pass in tests
    async def _no_auth():
        return None

    app.dependency_overrides[api_key_auth] = _no_auth
    # raise_server_exceptions=False so 501 handler fires instead of propagating
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def router_org_id(client):
    """Seed a scorecard directly into the router's singleton DB."""
    import apps.api.security_scorecard_router as _mod
    org = f"router-org-{uuid.uuid4().hex[:8]}"
    _seed_scorecard(_mod._scorecard, org, overall_score=78.0)
    return org


def test_router_list_categories(client):
    resp = client.get("/api/v1/scorecard/categories")
    assert resp.status_code == 200
    data = resp.json()
    assert "categories" in data
    assert data["total"] == 8


def test_router_generate_scorecard_returns_501(client):
    """generate_scorecard is not yet wired to real scanner data — must return 501."""
    org = f"gen-org-{uuid.uuid4().hex[:8]}"
    resp = client.post(f"/api/v1/scorecard/{org}/generate", json={"validity_days": 14})
    assert resp.status_code == 501
    data = resp.json()
    assert data["status"] == "not_implemented"
    assert data["error_category"] == "not_implemented"


def test_router_get_scorecard(client, router_org_id):
    resp = client.get(f"/api/v1/scorecard/{router_org_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["data"]["org_id"] == router_org_id


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
    """compare_orgs works with seeded data — generate calls return 501 (expected)."""
    import apps.api.security_scorecard_router as _mod
    org_a = f"cmp-a-{uuid.uuid4().hex[:8]}"
    org_b = f"cmp-b-{uuid.uuid4().hex[:8]}"
    # Seed both orgs directly — no generate_scorecard call
    _seed_scorecard(_mod._scorecard, org_a, overall_score=82.0)
    _seed_scorecard(_mod._scorecard, org_b, overall_score=68.0)
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
