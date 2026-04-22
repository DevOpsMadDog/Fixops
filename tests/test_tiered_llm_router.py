"""GAP-061 — Tiered LLM Context Router tests.

Covers:
 - tier enum validation ({metadata, targeted, full_file})
 - UNIQUE(org_id, rule_key) upsert dedup
 - estimate_llm_cost math on 3 scenarios (all-metadata, all-full-file, mixed)
 - preflight_estimate 3-tier breakdown
 - preflight total == sum of tiers
 - org_id isolation
 - endpoint smoke tests (register, list, preflight)

Usage:
    pytest tests/test_tiered_llm_router.py -v --timeout=10
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — mirror other router tests
# ---------------------------------------------------------------------------
_FIXOPS_ROOT = Path(__file__).parent.parent
_SUITE_CORE = _FIXOPS_ROOT / "suite-core"
_SUITE_API = _FIXOPS_ROOT / "suite-api"

for _p in [str(_FIXOPS_ROOT), str(_SUITE_CORE), str(_SUITE_API)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.ai_governance_engine import (  # noqa: E402
    AIGovernanceEngine,
    _TIER_COST_PER_1M_USD,
    _TIER_DEFAULT_MAX_TOKENS,
    _OUTPUT_TOKEN_FRACTION,
    _VALID_CONTEXT_TIERS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return AIGovernanceEngine(db_path=str(tmp_path / "ag.db"))


# ---------------------------------------------------------------------------
# 1. Tier enum validation
# ---------------------------------------------------------------------------


def test_tier_enum_contains_only_three(engine):
    assert _VALID_CONTEXT_TIERS == {"metadata", "targeted", "full_file"}


@pytest.mark.parametrize("tier", ["metadata", "targeted", "full_file"])
def test_tier_enum_accepts_valid(engine, tier):
    rec = engine.register_rule_context_requirement("org1", f"rule-{tier}", tier, 500)
    assert rec["tier"] == tier


@pytest.mark.parametrize("bogus", ["BOGUS", "full", "meta", "", "FULL_FILE", "token"])
def test_tier_enum_rejects_invalid(engine, bogus):
    with pytest.raises(ValueError):
        engine.register_rule_context_requirement("org1", "rx", bogus, 100)


def test_tier_enum_rejects_none(engine):
    with pytest.raises(ValueError):
        engine.register_rule_context_requirement("org1", "rx", None, 100)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. UNIQUE(org_id, rule_key) upsert dedup
# ---------------------------------------------------------------------------


def test_upsert_same_org_and_key_reuses_id(engine):
    r1 = engine.register_rule_context_requirement("org1", "ruleA", "metadata", 500)
    r2 = engine.register_rule_context_requirement("org1", "ruleA", "targeted", 4000)
    assert r1["id"] == r2["id"], "UNIQUE(org_id, rule_key) should upsert not insert"
    lst = engine.list_rule_context_requirements("org1")
    assert len(lst) == 1
    assert lst[0]["tier"] == "targeted"
    assert lst[0]["max_tokens"] == 4000


def test_upsert_preserves_created_at(engine):
    r1 = engine.register_rule_context_requirement("org1", "ruleA", "metadata", 500)
    r2 = engine.register_rule_context_requirement("org1", "ruleA", "full_file", 32000)
    assert r1["created_at"] == r2["created_at"]


def test_different_rule_keys_different_rows(engine):
    engine.register_rule_context_requirement("org1", "ruleA", "metadata", 500)
    engine.register_rule_context_requirement("org1", "ruleB", "targeted", 4000)
    assert len(engine.list_rule_context_requirements("org1")) == 2


def test_empty_rule_key_rejected(engine):
    with pytest.raises(ValueError):
        engine.register_rule_context_requirement("org1", "", "metadata", 500)
    with pytest.raises(ValueError):
        engine.register_rule_context_requirement("org1", "   ", "metadata", 500)


def test_empty_org_id_rejected(engine):
    with pytest.raises(ValueError):
        engine.register_rule_context_requirement("", "ruleA", "metadata", 500)


def test_max_tokens_must_be_positive(engine):
    with pytest.raises(ValueError):
        engine.register_rule_context_requirement("org1", "ruleA", "metadata", 0)
    with pytest.raises(ValueError):
        engine.register_rule_context_requirement("org1", "ruleA", "metadata", -10)
    with pytest.raises(ValueError):
        engine.register_rule_context_requirement("org1", "ruleA", "metadata", "notanint")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 3. estimate_llm_cost math correctness — 3 scenarios
# ---------------------------------------------------------------------------


def _expected_cost(tier: str, max_tokens: int, file_count: int) -> float:
    tokens_in = int(max_tokens * (1.0 - _OUTPUT_TOKEN_FRACTION)) * file_count
    tokens_out = int(max_tokens * _OUTPUT_TOKEN_FRACTION) * file_count
    return round((tokens_in + tokens_out) / 1_000_000.0 * _TIER_COST_PER_1M_USD[tier], 6)


def test_estimate_all_metadata(engine):
    for key in ("r1", "r2", "r3"):
        engine.register_rule_context_requirement("org1", key, "metadata", 500)
    est = engine.estimate_llm_cost("org1", ["r1", "r2", "r3"], file_count=1)
    # All 3 under metadata
    md = est["by_tier"]["metadata"]
    assert set(md["rules"]) == {"r1", "r2", "r3"}
    assert est["by_tier"]["targeted"]["rules"] == []
    assert est["by_tier"]["full_file"]["rules"] == []
    expected = 3 * _expected_cost("metadata", 500, 1)
    assert est["total"]["est_cost_usd"] == pytest.approx(expected, abs=1e-6)


def test_estimate_all_full_file(engine):
    for key in ("r1", "r2"):
        engine.register_rule_context_requirement("org1", key, "full_file", 32_000)
    est = engine.estimate_llm_cost("org1", ["r1", "r2"], file_count=3)
    ff = est["by_tier"]["full_file"]
    assert set(ff["rules"]) == {"r1", "r2"}
    expected = 2 * _expected_cost("full_file", 32_000, 3)
    assert est["total"]["est_cost_usd"] == pytest.approx(expected, abs=1e-6)
    # Full_file is the most expensive tier — sanity
    assert _TIER_COST_PER_1M_USD["full_file"] > _TIER_COST_PER_1M_USD["targeted"]
    assert _TIER_COST_PER_1M_USD["targeted"] > _TIER_COST_PER_1M_USD["metadata"]


def test_estimate_mixed_tiers(engine):
    engine.register_rule_context_requirement("org1", "m1", "metadata", 500)
    engine.register_rule_context_requirement("org1", "t1", "targeted", 4_000)
    engine.register_rule_context_requirement("org1", "f1", "full_file", 32_000)
    est = engine.estimate_llm_cost("org1", ["m1", "t1", "f1"], file_count=2)
    assert est["by_tier"]["metadata"]["rules"] == ["m1"]
    assert est["by_tier"]["targeted"]["rules"] == ["t1"]
    assert est["by_tier"]["full_file"]["rules"] == ["f1"]
    expected = (
        _expected_cost("metadata", 500, 2)
        + _expected_cost("targeted", 4_000, 2)
        + _expected_cost("full_file", 32_000, 2)
    )
    assert est["total"]["est_cost_usd"] == pytest.approx(expected, abs=1e-6)


def test_unregistered_rules_default_to_metadata(engine):
    est = engine.estimate_llm_cost("org1", ["never-registered"], file_count=1)
    assert est["by_tier"]["metadata"]["rules"] == ["never-registered"]
    expected = _expected_cost("metadata", _TIER_DEFAULT_MAX_TOKENS["metadata"], 1)
    assert est["total"]["est_cost_usd"] == pytest.approx(expected, abs=1e-6)


def test_empty_rule_keys_returns_zero(engine):
    est = engine.estimate_llm_cost("org1", [], file_count=1)
    assert est["total"]["rules"] == 0
    assert est["total"]["est_cost_usd"] == 0.0
    for tier_bucket in est["by_tier"].values():
        assert tier_bucket["rules"] == []
        assert tier_bucket["est_tokens_in"] == 0


def test_invalid_rule_keys_type_raises(engine):
    with pytest.raises(ValueError):
        engine.estimate_llm_cost("org1", "not-a-list", file_count=1)  # type: ignore[arg-type]


def test_file_count_must_be_ge_1(engine):
    with pytest.raises(ValueError):
        engine.estimate_llm_cost("org1", ["rule-a"], file_count=0)
    with pytest.raises(ValueError):
        engine.estimate_llm_cost("org1", ["rule-a"], file_count=-1)


def test_file_count_multiplies_tokens(engine):
    engine.register_rule_context_requirement("org1", "r1", "targeted", 4_000)
    est1 = engine.estimate_llm_cost("org1", ["r1"], file_count=1)
    est5 = engine.estimate_llm_cost("org1", ["r1"], file_count=5)
    assert est5["total"]["est_tokens_in"] == 5 * est1["total"]["est_tokens_in"]
    assert est5["total"]["est_tokens_out"] == 5 * est1["total"]["est_tokens_out"]


# ---------------------------------------------------------------------------
# 4. preflight_estimate — 3-tier breakdown and totals
# ---------------------------------------------------------------------------


def test_preflight_returns_three_tier_breakdown(engine):
    engine.register_rule_context_requirement("org1", "m1", "metadata", 500)
    engine.register_rule_context_requirement("org1", "t1", "targeted", 4_000)
    engine.register_rule_context_requirement("org1", "f1", "full_file", 32_000)
    pre = engine.preflight_estimate("org1", ["m1", "t1", "f1"], file_count=1)
    assert set(pre["by_tier"].keys()) == {"metadata", "targeted", "full_file"}
    assert pre["tier_distribution"] == {"metadata": 1, "targeted": 1, "full_file": 1}


def test_preflight_total_equals_sum_of_tiers(engine):
    engine.register_rule_context_requirement("org1", "m1", "metadata", 500)
    engine.register_rule_context_requirement("org1", "t1", "targeted", 4_000)
    engine.register_rule_context_requirement("org1", "f1", "full_file", 32_000)
    pre = engine.preflight_estimate("org1", ["m1", "t1", "f1"], file_count=4)
    tier_sum = sum(b["est_cost_usd"] for b in pre["by_tier"].values())
    assert pre["total"]["est_cost_usd"] == pytest.approx(round(tier_sum, 6), abs=1e-6)
    assert pre["total"]["est_tokens_in"] == sum(
        b["est_tokens_in"] for b in pre["by_tier"].values()
    )
    assert pre["total"]["est_tokens_out"] == sum(
        b["est_tokens_out"] for b in pre["by_tier"].values()
    )


def test_preflight_summary_contains_expected_fields(engine):
    engine.register_rule_context_requirement("org1", "m1", "metadata", 500)
    pre = engine.preflight_estimate("org1", ["m1"], file_count=2)
    s = pre["summary"]
    assert "Pre-flight" in s
    assert "$" in s
    assert "metadata=1" in s
    assert "2 file" in s


def test_preflight_empty_rules_summary_zero(engine):
    pre = engine.preflight_estimate("org1", [], file_count=1)
    assert pre["total"]["rules"] == 0
    assert pre["total"]["est_cost_usd"] == 0.0


# ---------------------------------------------------------------------------
# 5. org_id isolation
# ---------------------------------------------------------------------------


def test_org_isolation_list(engine):
    engine.register_rule_context_requirement("org1", "rule-a", "metadata", 500)
    engine.register_rule_context_requirement("org2", "rule-a", "full_file", 32_000)
    l1 = engine.list_rule_context_requirements("org1")
    l2 = engine.list_rule_context_requirements("org2")
    assert len(l1) == 1 and l1[0]["tier"] == "metadata"
    assert len(l2) == 1 and l2[0]["tier"] == "full_file"


def test_org_isolation_estimate(engine):
    # same rule_key, different tiers per org → different cost
    engine.register_rule_context_requirement("org1", "rx", "metadata", 500)
    engine.register_rule_context_requirement("org2", "rx", "full_file", 32_000)
    e1 = engine.estimate_llm_cost("org1", ["rx"], file_count=1)
    e2 = engine.estimate_llm_cost("org2", ["rx"], file_count=1)
    assert e1["by_tier"]["metadata"]["rules"] == ["rx"]
    assert e2["by_tier"]["full_file"]["rules"] == ["rx"]
    assert e2["total"]["est_cost_usd"] > e1["total"]["est_cost_usd"]


def test_org3_empty_list(engine):
    engine.register_rule_context_requirement("org1", "rule-a", "metadata", 500)
    assert engine.list_rule_context_requirements("org3") == []


# ---------------------------------------------------------------------------
# 6. Endpoint smoke tests
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient wired to a fresh AIGovernanceEngine-backed router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Force the router to use a fresh engine by resetting the singleton
    import apps.api.ai_orchestrator_router as router_mod

    fresh = AIGovernanceEngine(db_path=str(tmp_path / "router_ag.db"))
    monkeypatch.setattr(router_mod, "_AI_GOV_SINGLETON", fresh, raising=False)

    app = FastAPI()
    app.include_router(router_mod.router)
    return TestClient(app)


def test_endpoint_register_context_requirement(client):
    resp = client.post(
        "/api/v1/ai-orchestrator/context-requirement?org_id=org1",
        json={"rule_key": "owasp-a01", "tier": "targeted", "max_tokens": 4000},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["rule_key"] == "owasp-a01"
    assert data["tier"] == "targeted"
    assert data["max_tokens"] == 4000


def test_endpoint_register_invalid_tier_422(client):
    resp = client.post(
        "/api/v1/ai-orchestrator/context-requirement?org_id=org1",
        json={"rule_key": "rx", "tier": "BOGUS", "max_tokens": 500},
    )
    assert resp.status_code == 422


def test_endpoint_list_context_requirements(client):
    client.post(
        "/api/v1/ai-orchestrator/context-requirement?org_id=org1",
        json={"rule_key": "rule-a", "tier": "metadata", "max_tokens": 500},
    )
    client.post(
        "/api/v1/ai-orchestrator/context-requirement?org_id=org1",
        json={"rule_key": "rule-b", "tier": "full_file", "max_tokens": 32000},
    )
    resp = client.get("/api/v1/ai-orchestrator/context-requirements?org_id=org1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    keys = {item["rule_key"] for item in body["items"]}
    assert keys == {"rule-a", "rule-b"}


def test_endpoint_preflight_estimate(client):
    client.post(
        "/api/v1/ai-orchestrator/context-requirement?org_id=org1",
        json={"rule_key": "m1", "tier": "metadata", "max_tokens": 500},
    )
    client.post(
        "/api/v1/ai-orchestrator/context-requirement?org_id=org1",
        json={"rule_key": "f1", "tier": "full_file", "max_tokens": 32000},
    )
    resp = client.post(
        "/api/v1/ai-orchestrator/preflight-estimate?org_id=org1",
        json={"rule_keys": ["m1", "f1"], "file_count": 2},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body["by_tier"].keys()) == {"metadata", "targeted", "full_file"}
    assert body["tier_distribution"]["metadata"] == 1
    assert body["tier_distribution"]["full_file"] == 1
    assert body["total"]["rules"] == 2
    assert body["total"]["est_cost_usd"] > 0


def test_endpoint_preflight_rejects_bad_file_count(client):
    resp = client.post(
        "/api/v1/ai-orchestrator/preflight-estimate?org_id=org1",
        json={"rule_keys": ["m1"], "file_count": 0},
    )
    assert resp.status_code == 422
