"""Tests for AssetCriticalityEngine — 37 tests covering all methods and edge cases."""
from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.asset_criticality_engine import AssetCriticalityEngine, _compute_tier

ORG = "org-ac-test"
ORG2 = "org-ac-other"


@pytest.fixture
def engine(tmp_path):
    return AssetCriticalityEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_asset(engine, org=ORG, asset_type="server", **kwargs):
    return engine.register_asset(
        org_id=org,
        asset_name=kwargs.get("asset_name", "Web Server"),
        asset_type=asset_type,
        owner=kwargs.get("owner", "ops-team"),
        business_function=kwargs.get("business_function", "Customer portal"),
        data_classification=kwargs.get("data_classification", "confidential"),
        availability_requirement=kwargs.get("availability_requirement", "high"),
        integrity_requirement=kwargs.get("integrity_requirement", "high"),
        confidentiality_requirement=kwargs.get("confidentiality_requirement", "critical"),
    )


def _score_asset(engine, asset_id, org=ORG, factors=None):
    if factors is None:
        factors = [
            {"factor_name": "business_impact", "factor_category": "impact", "weight": 2.0, "value": 8.0},
            {"factor_name": "exposure", "factor_category": "risk", "weight": 1.0, "value": 6.0},
        ]
    return engine.score_asset(asset_id, org, factors)


# ---------------------------------------------------------------------------
# _compute_tier unit tests
# ---------------------------------------------------------------------------

def test_compute_tier_critical_exact_boundary():
    assert _compute_tier(80.0) == "tier-1-critical"


def test_compute_tier_critical_above():
    assert _compute_tier(95.0) == "tier-1-critical"


def test_compute_tier_high_exact_boundary():
    assert _compute_tier(60.0) == "tier-2-high"


def test_compute_tier_high_upper():
    assert _compute_tier(79.9) == "tier-2-high"


def test_compute_tier_medium_exact_boundary():
    assert _compute_tier(40.0) == "tier-3-medium"


def test_compute_tier_medium_upper():
    assert _compute_tier(59.9) == "tier-3-medium"


def test_compute_tier_low():
    assert _compute_tier(39.9) == "tier-4-low"


def test_compute_tier_zero():
    assert _compute_tier(0.0) == "tier-4-low"


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

def test_register_asset_returns_dict(engine):
    a = _make_asset(engine)
    assert isinstance(a, dict)
    assert a["org_id"] == ORG
    assert a["criticality_score"] == 0.0
    assert a["criticality_tier"] == "unassessed"


def test_register_asset_invalid_type(engine):
    with pytest.raises(ValueError, match="asset_type"):
        engine.register_asset(ORG, "Bad", "unknown_type")


def test_register_asset_invalid_classification(engine):
    with pytest.raises(ValueError, match="data_classification"):
        engine.register_asset(ORG, "Bad", "server", data_classification="top_secret")


def test_register_asset_invalid_requirement(engine):
    with pytest.raises(ValueError, match="availability_requirement"):
        engine.register_asset(ORG, "Bad", "server", availability_requirement="extreme")


def test_register_asset_has_id_and_created_at(engine):
    a = _make_asset(engine)
    assert "id" in a and a["id"]
    assert "created_at" in a and a["created_at"]


def test_register_asset_all_types(engine):
    types = ["server", "workstation", "network", "application", "database",
             "cloud", "iot", "mobile", "container"]
    for t in types:
        a = engine.register_asset(ORG, f"Asset-{t}", t)
        assert a["asset_type"] == t


# ---------------------------------------------------------------------------
# score_asset
# ---------------------------------------------------------------------------

def test_score_asset_formula(engine):
    # weight=2, value=8 → contribution=1.6; weight=1, value=6 → contribution=0.6
    # score = (1.6+0.6)/(2+1)*100 = 2.2/3*100 ≈ 73.33
    a = _make_asset(engine)
    result = _score_asset(engine, a["id"])
    expected = (2.0 * 8.0 / 10.0 + 1.0 * 6.0 / 10.0) / (2.0 + 1.0) * 100.0
    assert abs(result["criticality_score"] - expected) < 0.01


def test_score_asset_tier_critical(engine):
    a = _make_asset(engine)
    # weight=1, value=10 → score=100 → tier-1-critical
    result = engine.score_asset(a["id"], ORG, [
        {"factor_name": "f1", "factor_category": "impact", "weight": 1.0, "value": 10.0}
    ])
    assert result["criticality_tier"] == "tier-1-critical"
    assert abs(result["criticality_score"] - 100.0) < 0.01


def test_score_asset_tier_high(engine):
    a = _make_asset(engine)
    # value=7 → score=70
    result = engine.score_asset(a["id"], ORG, [
        {"factor_name": "f1", "factor_category": "c", "weight": 1.0, "value": 7.0}
    ])
    assert result["criticality_tier"] == "tier-2-high"


def test_score_asset_tier_medium(engine):
    a = _make_asset(engine)
    result = engine.score_asset(a["id"], ORG, [
        {"factor_name": "f1", "factor_category": "c", "weight": 1.0, "value": 5.0}
    ])
    assert result["criticality_tier"] == "tier-3-medium"


def test_score_asset_tier_low(engine):
    a = _make_asset(engine)
    result = engine.score_asset(a["id"], ORG, [
        {"factor_name": "f1", "factor_category": "c", "weight": 1.0, "value": 3.0}
    ])
    assert result["criticality_tier"] == "tier-4-low"


def test_score_asset_empty_factors_raises(engine):
    a = _make_asset(engine)
    with pytest.raises(ValueError, match="factors"):
        engine.score_asset(a["id"], ORG, [])


def test_score_asset_updates_last_assessed(engine):
    a = _make_asset(engine)
    assert a["last_assessed"] == ""
    result = _score_asset(engine, a["id"])
    assert result["last_assessed"] != ""


def test_score_asset_includes_factors_list(engine):
    a = _make_asset(engine)
    result = _score_asset(engine, a["id"])
    assert "factors" in result
    assert len(result["factors"]) == 2


def test_score_asset_not_found_returns_none(engine):
    result = engine.score_asset("nonexistent", ORG, [
        {"factor_name": "f1", "factor_category": "c", "weight": 1.0, "value": 5.0}
    ])
    assert result is None


# ---------------------------------------------------------------------------
# add_dependency / get_asset
# ---------------------------------------------------------------------------

def test_add_dependency_returns_dict(engine):
    a1 = _make_asset(engine, asset_name="App")
    a2 = _make_asset(engine, asset_name="DB")
    dep = engine.add_dependency(a1["id"], ORG, a2["id"], "technical", "high")
    assert dep["asset_id"] == a1["id"]
    assert dep["depends_on_asset_id"] == a2["id"]
    assert dep["dependency_type"] == "technical"


def test_add_dependency_invalid_type(engine):
    a1 = _make_asset(engine, asset_name="A")
    a2 = _make_asset(engine, asset_name="B")
    with pytest.raises(ValueError, match="dependency_type"):
        engine.add_dependency(a1["id"], ORG, a2["id"], "invalid_type")


def test_add_dependency_invalid_impact(engine):
    a1 = _make_asset(engine, asset_name="A")
    a2 = _make_asset(engine, asset_name="B")
    with pytest.raises(ValueError, match="criticality_impact"):
        engine.add_dependency(a1["id"], ORG, a2["id"], "technical", "extreme")


def test_get_asset_includes_factors_and_dependencies(engine):
    a1 = _make_asset(engine, asset_name="App")
    a2 = _make_asset(engine, asset_name="DB")
    _score_asset(engine, a1["id"])
    engine.add_dependency(a1["id"], ORG, a2["id"])
    result = engine.get_asset(a1["id"], ORG)
    assert isinstance(result["factors"], list)
    assert isinstance(result["dependencies"], list)
    assert len(result["dependencies"]) == 1


def test_get_asset_wrong_org_returns_none(engine):
    a = _make_asset(engine)
    assert engine.get_asset(a["id"], ORG2) is None


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------

def test_list_assets_returns_all(engine):
    _make_asset(engine, asset_type="server", asset_name="S1")
    _make_asset(engine, asset_type="database", asset_name="D1")
    results = engine.list_assets(ORG)
    assert len(results) == 2


def test_list_assets_tier_filter(engine):
    a1 = _make_asset(engine, asset_name="Critical")
    engine.score_asset(a1["id"], ORG, [
        {"factor_name": "f1", "factor_category": "c", "weight": 1.0, "value": 10.0}
    ])
    a2 = _make_asset(engine, asset_name="Low")
    engine.score_asset(a2["id"], ORG, [
        {"factor_name": "f1", "factor_category": "c", "weight": 1.0, "value": 2.0}
    ])
    results = engine.list_assets(ORG, criticality_tier="tier-1-critical")
    assert len(results) == 1
    assert results[0]["asset_name"] == "Critical"


def test_list_assets_type_filter(engine):
    _make_asset(engine, asset_type="server", asset_name="S1")
    _make_asset(engine, asset_type="cloud", asset_name="C1")
    results = engine.list_assets(ORG, asset_type="cloud")
    assert len(results) == 1


def test_list_assets_org_isolation(engine):
    _make_asset(engine, org=ORG)
    _make_asset(engine, org=ORG2)
    assert len(engine.list_assets(ORG)) == 1
    assert len(engine.list_assets(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_critical_path (BFS)
# ---------------------------------------------------------------------------

def test_get_critical_path_direct_dependency(engine):
    a1 = _make_asset(engine, asset_name="App")
    a2 = _make_asset(engine, asset_name="DB")
    engine.add_dependency(a1["id"], ORG, a2["id"])
    path = engine.get_critical_path(ORG, a1["id"])
    ids = [p["id"] for p in path]
    assert a2["id"] in ids


def test_get_critical_path_transitive(engine):
    a1 = _make_asset(engine, asset_name="App")
    a2 = _make_asset(engine, asset_name="DB")
    a3 = _make_asset(engine, asset_name="Storage")
    engine.add_dependency(a1["id"], ORG, a2["id"])
    engine.add_dependency(a2["id"], ORG, a3["id"])
    path = engine.get_critical_path(ORG, a1["id"])
    ids = [p["id"] for p in path]
    assert a2["id"] in ids
    assert a3["id"] in ids


def test_get_critical_path_max_3_hops(engine):
    # Chain: a1 -> a2 -> a3 -> a4 -> a5 (hop 4 should be excluded)
    assets = [_make_asset(engine, asset_name=f"Asset{i}") for i in range(5)]
    for i in range(4):
        engine.add_dependency(assets[i]["id"], ORG, assets[i + 1]["id"])
    path = engine.get_critical_path(ORG, assets[0]["id"])
    ids = [p["id"] for p in path]
    # hop 1=assets[1], hop 2=assets[2], hop 3=assets[3] → included; hop 4=assets[4] excluded
    assert assets[1]["id"] in ids
    assert assets[2]["id"] in ids
    assert assets[3]["id"] in ids
    assert assets[4]["id"] not in ids


def test_get_critical_path_circular_safe(engine):
    a1 = _make_asset(engine, asset_name="A1")
    a2 = _make_asset(engine, asset_name="A2")
    engine.add_dependency(a1["id"], ORG, a2["id"])
    engine.add_dependency(a2["id"], ORG, a1["id"])  # circular
    # Should not infinite loop
    path = engine.get_critical_path(ORG, a1["id"])
    assert isinstance(path, list)


def test_get_critical_path_no_deps_empty(engine):
    a = _make_asset(engine)
    path = engine.get_critical_path(ORG, a["id"])
    assert path == []


# ---------------------------------------------------------------------------
# get_criticality_summary
# ---------------------------------------------------------------------------

def test_get_criticality_summary_empty(engine):
    result = engine.get_criticality_summary(ORG)
    assert result["avg_score"] == 0.0
    assert result["unassessed_count"] == 0
    assert result["most_critical"] == []


def test_get_criticality_summary_unassessed_count(engine):
    _make_asset(engine, asset_name="A1")
    _make_asset(engine, asset_name="A2")
    result = engine.get_criticality_summary(ORG)
    assert result["unassessed_count"] == 2


def test_get_criticality_summary_count_by_tier(engine):
    a1 = _make_asset(engine, asset_name="Critical1")
    engine.score_asset(a1["id"], ORG, [
        {"factor_name": "f", "factor_category": "c", "weight": 1.0, "value": 10.0}
    ])
    a2 = _make_asset(engine, asset_name="Low1")
    engine.score_asset(a2["id"], ORG, [
        {"factor_name": "f", "factor_category": "c", "weight": 1.0, "value": 2.0}
    ])
    result = engine.get_criticality_summary(ORG)
    assert result["count_by_tier"]["tier-1-critical"] == 1
    assert result["count_by_tier"]["tier-4-low"] == 1


def test_get_criticality_summary_top5_most_critical(engine):
    for i in range(6):
        a = _make_asset(engine, asset_name=f"Asset{i}")
        engine.score_asset(a["id"], ORG, [
            {"factor_name": "f", "factor_category": "c", "weight": 1.0, "value": float(i + 4)}
        ])
    result = engine.get_criticality_summary(ORG)
    assert len(result["most_critical"]) <= 5


def test_get_criticality_summary_avg_score_excludes_unassessed(engine):
    a1 = _make_asset(engine, asset_name="Scored")
    engine.score_asset(a1["id"], ORG, [
        {"factor_name": "f", "factor_category": "c", "weight": 1.0, "value": 8.0}
    ])
    _make_asset(engine, asset_name="Unscored")  # still unassessed
    result = engine.get_criticality_summary(ORG)
    # avg_score should be computed only from scored assets
    assert result["avg_score"] == 80.0
