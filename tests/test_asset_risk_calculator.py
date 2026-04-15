"""Tests for AssetRiskCalculator — Beast Mode suite."""

from __future__ import annotations

import os
import tempfile
import pytest

from core.asset_risk_calculator import AssetRiskCalculator


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_asset_risk.db")
    return AssetRiskCalculator(db_path=db)


ORG = "org-test-001"
ORG2 = "org-test-002"


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

def test_register_asset_basic(engine):
    asset = engine.register_asset(ORG, {"name": "web-server-01", "asset_type": "server"})
    assert asset["asset_id"]
    assert asset["name"] == "web-server-01"
    assert asset["asset_type"] == "server"
    assert asset["org_id"] == ORG


def test_register_asset_all_fields(engine):
    data = {
        "name": "prod-db",
        "asset_type": "database",
        "criticality": "critical",
        "exposure": "internet_facing",
        "owner": "dba-team",
        "tags": ["prod", "pci"],
    }
    asset = engine.register_asset(ORG, data)
    assert asset["criticality"] == "critical"
    assert asset["exposure"] == "internet_facing"
    assert asset["tags"] == ["prod", "pci"]


def test_register_asset_invalid_type(engine):
    with pytest.raises(ValueError, match="asset_type"):
        engine.register_asset(ORG, {"name": "x", "asset_type": "spaceship"})


def test_register_asset_invalid_criticality(engine):
    with pytest.raises(ValueError, match="criticality"):
        engine.register_asset(ORG, {"name": "x", "criticality": "extreme"})


def test_register_asset_invalid_exposure(engine):
    with pytest.raises(ValueError, match="exposure"):
        engine.register_asset(ORG, {"name": "x", "exposure": "cloud"})


def test_register_asset_missing_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_asset(ORG, {"asset_type": "server"})


def test_register_all_asset_types(engine):
    types = ["server", "workstation", "network_device", "cloud_instance",
             "database", "application", "iot"]
    for t in types:
        a = engine.register_asset(ORG, {"name": f"asset-{t}", "asset_type": t})
        assert a["asset_type"] == t


# ---------------------------------------------------------------------------
# list_assets / get_asset
# ---------------------------------------------------------------------------

def test_list_assets_empty(engine):
    assert engine.list_assets(ORG) == []


def test_list_assets_returns_own_org_only(engine):
    engine.register_asset(ORG, {"name": "a1"})
    engine.register_asset(ORG2, {"name": "a2"})
    assets = engine.list_assets(ORG)
    assert len(assets) == 1
    assert assets[0]["name"] == "a1"


def test_list_assets_filter_type(engine):
    engine.register_asset(ORG, {"name": "srv", "asset_type": "server"})
    engine.register_asset(ORG, {"name": "db", "asset_type": "database"})
    servers = engine.list_assets(ORG, asset_type="server")
    assert len(servers) == 1
    assert servers[0]["name"] == "srv"


def test_list_assets_filter_criticality(engine):
    engine.register_asset(ORG, {"name": "crit", "criticality": "critical"})
    engine.register_asset(ORG, {"name": "low", "criticality": "low"})
    crits = engine.list_assets(ORG, criticality="critical")
    assert len(crits) == 1
    assert crits[0]["name"] == "crit"


def test_get_asset_found(engine):
    created = engine.register_asset(ORG, {"name": "srv"})
    fetched = engine.get_asset(ORG, created["asset_id"])
    assert fetched is not None
    assert fetched["asset_id"] == created["asset_id"]


def test_get_asset_not_found(engine):
    assert engine.get_asset(ORG, "nonexistent-id") is None


def test_get_asset_org_isolation(engine):
    created = engine.register_asset(ORG, {"name": "srv"})
    # Different org cannot see it
    assert engine.get_asset(ORG2, created["asset_id"]) is None


# ---------------------------------------------------------------------------
# calculate_risk
# ---------------------------------------------------------------------------

def test_calculate_risk_basic(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    factors = [{"vuln_score": 80, "threat_score": 60, "exposure_score": 50, "compliance_score": 40}]
    score = engine.calculate_risk(ORG, asset["asset_id"], factors)
    assert "composite_score" in score
    assert score["risk_level"] in ("critical", "high", "medium", "low", "minimal")
    assert score["score_id"]


def test_calculate_risk_weights(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    # All scores = 100 → composite = 100
    factors = [{"vuln_score": 100, "threat_score": 100,
                "exposure_score": 100, "compliance_score": 100}]
    score = engine.calculate_risk(ORG, asset["asset_id"], factors)
    assert score["composite_score"] == 100.0
    assert score["risk_level"] == "critical"


def test_calculate_risk_zero_scores(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    factors = [{"vuln_score": 0, "threat_score": 0,
                "exposure_score": 0, "compliance_score": 0}]
    score = engine.calculate_risk(ORG, asset["asset_id"], factors)
    assert score["composite_score"] == 0.0
    assert score["risk_level"] == "minimal"


def test_calculate_risk_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.calculate_risk(ORG, "bad-id", [])


def test_risk_levels(engine):
    cases = [
        (80, "critical"), (60, "high"), (40, "medium"), (20, "low"), (0, "minimal")
    ]
    for score_val, expected_level in cases:
        asset = engine.register_asset(ORG, {"name": f"asset-{score_val}"})
        factors = [{"vuln_score": score_val, "threat_score": score_val,
                    "exposure_score": score_val, "compliance_score": score_val}]
        score = engine.calculate_risk(ORG, asset["asset_id"], factors)
        assert score["risk_level"] == expected_level, f"Expected {expected_level} for score {score_val}"


# ---------------------------------------------------------------------------
# get_latest_score / list_scores
# ---------------------------------------------------------------------------

def test_get_latest_score_none(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    assert engine.get_latest_score(ORG, asset["asset_id"]) is None


def test_get_latest_score_after_calculation(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    factors = [{"vuln_score": 70}]
    engine.calculate_risk(ORG, asset["asset_id"], factors)
    score = engine.get_latest_score(ORG, asset["asset_id"])
    assert score is not None
    assert score["asset_id"] == asset["asset_id"]


def test_list_scores_empty(engine):
    assert engine.list_scores(ORG) == []


def test_list_scores_org_isolation(engine):
    a1 = engine.register_asset(ORG, {"name": "a1"})
    a2 = engine.register_asset(ORG2, {"name": "a2"})
    engine.calculate_risk(ORG, a1["asset_id"], [{"vuln_score": 50}])
    engine.calculate_risk(ORG2, a2["asset_id"], [{"vuln_score": 50}])
    scores = engine.list_scores(ORG)
    assert len(scores) == 1
    assert scores[0]["org_id"] == ORG


def test_list_scores_filter_risk_level(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    engine.calculate_risk(ORG, asset["asset_id"],
                          [{"vuln_score": 90, "threat_score": 90,
                            "exposure_score": 90, "compliance_score": 90}])
    critical = engine.list_scores(ORG, risk_level="critical")
    assert len(critical) == 1
    low = engine.list_scores(ORG, risk_level="low")
    assert len(low) == 0


# ---------------------------------------------------------------------------
# add_risk_factor / list_risk_factors
# ---------------------------------------------------------------------------

def test_add_risk_factor(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    factor = engine.add_risk_factor(ORG, asset["asset_id"], {
        "factor_type": "vulnerability",
        "factor_name": "CVE-2024-1234",
        "impact": 8.5,
        "description": "Critical RCE",
    })
    assert factor["factor_id"]
    assert factor["factor_name"] == "CVE-2024-1234"


def test_add_risk_factor_invalid_type(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    with pytest.raises(ValueError, match="factor_type"):
        engine.add_risk_factor(ORG, asset["asset_id"], {
            "factor_type": "unknown_type",
            "factor_name": "x",
        })


def test_add_risk_factor_asset_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.add_risk_factor(ORG, "bad-id", {"factor_name": "x"})


def test_list_risk_factors(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    engine.add_risk_factor(ORG, asset["asset_id"], {"factor_type": "vulnerability", "factor_name": "CVE-A"})
    engine.add_risk_factor(ORG, asset["asset_id"], {"factor_type": "misconfiguration", "factor_name": "open port"})
    factors = engine.list_risk_factors(ORG, asset["asset_id"])
    assert len(factors) == 2


def test_list_risk_factors_org_isolation(engine):
    a1 = engine.register_asset(ORG, {"name": "a1"})
    a2 = engine.register_asset(ORG2, {"name": "a2"})
    engine.add_risk_factor(ORG, a1["asset_id"], {"factor_name": "f1"})
    # ORG2 should see no factors for a1
    assert engine.list_risk_factors(ORG2, a1["asset_id"]) == []


def test_all_factor_types(engine):
    asset = engine.register_asset(ORG, {"name": "srv"})
    types = ["vulnerability", "misconfiguration", "exposure", "threat_intel", "compliance"]
    for ft in types:
        f = engine.add_risk_factor(ORG, asset["asset_id"], {
            "factor_type": ft, "factor_name": f"factor-{ft}"
        })
        assert f["factor_type"] == ft


# ---------------------------------------------------------------------------
# get_risk_stats
# ---------------------------------------------------------------------------

def test_get_risk_stats_empty(engine):
    stats = engine.get_risk_stats(ORG)
    assert stats["total_assets"] == 0
    assert stats["avg_composite_score"] == 0.0
    assert stats["critical_assets"] == []


def test_get_risk_stats_with_data(engine):
    a1 = engine.register_asset(ORG, {"name": "high-risk",
                                      "criticality": "critical",
                                      "exposure": "internet_facing"})
    a2 = engine.register_asset(ORG, {"name": "low-risk",
                                      "criticality": "low",
                                      "exposure": "air_gapped"})
    engine.calculate_risk(ORG, a1["asset_id"],
                          [{"vuln_score": 90, "threat_score": 90,
                            "exposure_score": 90, "compliance_score": 90}])
    engine.calculate_risk(ORG, a2["asset_id"],
                          [{"vuln_score": 10, "threat_score": 10,
                            "exposure_score": 10, "compliance_score": 10}])
    stats = engine.get_risk_stats(ORG)
    assert stats["total_assets"] == 2
    assert stats["avg_composite_score"] > 0
    assert "high-risk" in stats["critical_assets"]


def test_get_risk_stats_internet_facing_critical(engine):
    asset = engine.register_asset(ORG, {
        "name": "exposed",
        "criticality": "critical",
        "exposure": "internet_facing",
    })
    engine.calculate_risk(ORG, asset["asset_id"],
                          [{"vuln_score": 90, "threat_score": 90,
                            "exposure_score": 90, "compliance_score": 90}])
    stats = engine.get_risk_stats(ORG)
    assert stats["internet_facing_critical"] == 1


def test_get_risk_stats_org_isolation(engine):
    engine.register_asset(ORG, {"name": "a1"})
    engine.register_asset(ORG, {"name": "a2"})
    engine.register_asset(ORG2, {"name": "b1"})
    stats = engine.get_risk_stats(ORG)
    assert stats["total_assets"] == 2
    stats2 = engine.get_risk_stats(ORG2)
    assert stats2["total_assets"] == 1
