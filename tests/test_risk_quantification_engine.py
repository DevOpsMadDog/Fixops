"""Tests for RiskQuantificationEngine — FAIR-based financial risk quantification.

Covers: scenario CRUD, Monte Carlo simulation, treatments, financial impacts, stats.
"""
import os
import tempfile
import pytest

from core.risk_quantification_engine import RiskQuantificationEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "rq_test.db")
    return RiskQuantificationEngine(db_path=db)


# ---------------------------------------------------------------------------
# Scenario creation
# ---------------------------------------------------------------------------

def test_create_scenario_basic(engine):
    s = engine.create_scenario("org1", {"name": "Ransomware Attack"})
    assert s["scenario_id"]
    assert s["name"] == "Ransomware Attack"
    assert s["org_id"] == "org1"
    assert s["threat_actor"] == "cybercriminal"
    assert s["attack_vector"] == "phishing"
    assert s["target_asset_type"] == "data"


def test_create_scenario_full_params(engine):
    data = {
        "name": "Nation State APT",
        "threat_actor": "nation_state",
        "attack_vector": "supply_chain",
        "target_asset_type": "infrastructure",
        "likelihood_pct": 15.0,
        "minimum_loss": 100_000.0,
        "maximum_loss": 5_000_000.0,
    }
    s = engine.create_scenario("org1", data)
    assert s["threat_actor"] == "nation_state"
    assert s["attack_vector"] == "supply_chain"
    assert s["likelihood_pct"] == 15.0
    assert s["minimum_loss"] == 100_000.0
    assert s["maximum_loss"] == 5_000_000.0


def test_create_scenario_computes_expected_loss(engine):
    data = {
        "name": "Phishing",
        "likelihood_pct": 50.0,
        "minimum_loss": 0.0,
        "maximum_loss": 200_000.0,
    }
    s = engine.create_scenario("org1", data)
    # expected_loss = (50/100) * avg(0, 200_000) = 0.5 * 100_000 = 50_000
    assert s["expected_loss"] == pytest.approx(50_000.0)


def test_create_scenario_computes_ale(engine):
    data = {
        "name": "Credential Theft",
        "likelihood_pct": 80.0,
        "minimum_loss": 10_000.0,
        "maximum_loss": 90_000.0,
    }
    s = engine.create_scenario("org1", data)
    # ALE = ARO * SLE = 0.8 * avg(10_000, 90_000) = 0.8 * 50_000 = 40_000
    assert s["ale"] == pytest.approx(40_000.0)


def test_create_scenario_invalid_threat_actor_defaults(engine):
    s = engine.create_scenario("org1", {"name": "X", "threat_actor": "unknown_actor"})
    assert s["threat_actor"] == "cybercriminal"


def test_create_scenario_invalid_attack_vector_defaults(engine):
    s = engine.create_scenario("org1", {"name": "X", "attack_vector": "telekinesis"})
    assert s["attack_vector"] == "phishing"


def test_create_scenario_likelihood_clamped(engine):
    s = engine.create_scenario("org1", {"name": "X", "likelihood_pct": 150.0})
    assert s["likelihood_pct"] == 100.0


def test_create_scenario_has_uuid(engine):
    s = engine.create_scenario("org1", {"name": "UUID Test"})
    # UUID v4 format: 8-4-4-4-12
    parts = s["scenario_id"].split("-")
    assert len(parts) == 5


# ---------------------------------------------------------------------------
# Scenario retrieval and listing
# ---------------------------------------------------------------------------

def test_get_scenario(engine):
    s = engine.create_scenario("org1", {"name": "Retrieval Test"})
    fetched = engine.get_scenario("org1", s["scenario_id"])
    assert fetched is not None
    assert fetched["scenario_id"] == s["scenario_id"]


def test_get_scenario_wrong_org_returns_none(engine):
    s = engine.create_scenario("org1", {"name": "Tenant Test"})
    result = engine.get_scenario("org2", s["scenario_id"])
    assert result is None


def test_list_scenarios_empty(engine):
    assert engine.list_scenarios("org_empty") == []


def test_list_scenarios_returns_all(engine):
    engine.create_scenario("org1", {"name": "S1"})
    engine.create_scenario("org1", {"name": "S2"})
    engine.create_scenario("org2", {"name": "S3"})
    results = engine.list_scenarios("org1")
    assert len(results) == 2


def test_list_scenarios_tenant_isolation(engine):
    engine.create_scenario("orgA", {"name": "A-only"})
    engine.create_scenario("orgB", {"name": "B-only"})
    assert all(s["org_id"] == "orgA" for s in engine.list_scenarios("orgA"))


# ---------------------------------------------------------------------------
# Scenario update
# ---------------------------------------------------------------------------

def test_update_scenario_name(engine):
    s = engine.create_scenario("org1", {"name": "Old Name"})
    updated = engine.update_scenario("org1", s["scenario_id"], {"name": "New Name"})
    assert updated is True
    fetched = engine.get_scenario("org1", s["scenario_id"])
    assert fetched["name"] == "New Name"


def test_update_scenario_recomputes_ale(engine):
    s = engine.create_scenario("org1", {
        "name": "Recompute",
        "likelihood_pct": 10.0,
        "minimum_loss": 0.0,
        "maximum_loss": 100_000.0,
    })
    engine.update_scenario("org1", s["scenario_id"], {"likelihood_pct": 50.0})
    fetched = engine.get_scenario("org1", s["scenario_id"])
    # ALE = 0.5 * 50_000 = 25_000
    assert fetched["ale"] == pytest.approx(25_000.0)


def test_update_scenario_wrong_org_returns_false(engine):
    s = engine.create_scenario("org1", {"name": "Update Isolation"})
    result = engine.update_scenario("org2", s["scenario_id"], {"name": "Hacked"})
    assert result is False


def test_update_scenario_no_valid_fields_returns_false(engine):
    s = engine.create_scenario("org1", {"name": "Noop Update"})
    result = engine.update_scenario("org1", s["scenario_id"], {"nonexistent_field": "x"})
    assert result is False


# ---------------------------------------------------------------------------
# Monte Carlo simulation
# ---------------------------------------------------------------------------

def test_monte_carlo_returns_expected_keys(engine):
    s = engine.create_scenario("org1", {
        "name": "MC Test",
        "likelihood_pct": 60.0,
        "minimum_loss": 10_000.0,
        "maximum_loss": 500_000.0,
    })
    result = engine.run_monte_carlo("org1", s["scenario_id"], iterations=500)
    for key in ("mean", "median", "p95", "p99", "worst_case", "best_case", "iterations", "ran_at"):
        assert key in result


def test_monte_carlo_p99_gte_p95(engine):
    s = engine.create_scenario("org1", {
        "name": "MC Order Test",
        "likelihood_pct": 70.0,
        "minimum_loss": 1_000.0,
        "maximum_loss": 1_000_000.0,
    })
    result = engine.run_monte_carlo("org1", s["scenario_id"], iterations=1000)
    assert result["p99"] >= result["p95"]


def test_monte_carlo_worst_case_gte_best_case(engine):
    s = engine.create_scenario("org1", {
        "name": "MC Bounds",
        "likelihood_pct": 50.0,
        "minimum_loss": 5_000.0,
        "maximum_loss": 100_000.0,
    })
    result = engine.run_monte_carlo("org1", s["scenario_id"], iterations=200)
    assert result["worst_case"] >= result["best_case"]


def test_monte_carlo_invalid_scenario_raises(engine):
    with pytest.raises(ValueError):
        engine.run_monte_carlo("org1", "nonexistent-id", iterations=100)


# ---------------------------------------------------------------------------
# Risk Treatments
# ---------------------------------------------------------------------------

def test_create_treatment_basic(engine):
    s = engine.create_scenario("org1", {
        "name": "Treatment Test",
        "likelihood_pct": 40.0,
        "minimum_loss": 50_000.0,
        "maximum_loss": 200_000.0,
    })
    t = engine.create_treatment("org1", s["scenario_id"], {
        "treatment_type": "mitigate",
        "description": "Deploy MFA",
        "cost": 10_000.0,
        "risk_reduction_pct": 60.0,
    })
    assert t["treatment_id"]
    assert t["treatment_type"] == "mitigate"
    assert t["cost"] == 10_000.0
    assert t["risk_reduction_pct"] == 60.0


def test_create_treatment_computes_roi(engine):
    s = engine.create_scenario("org1", {
        "name": "ROI Test",
        "likelihood_pct": 50.0,
        "minimum_loss": 0.0,
        "maximum_loss": 200_000.0,  # expected_loss = 50_000
    })
    t = engine.create_treatment("org1", s["scenario_id"], {
        "cost": 5_000.0,
        "risk_reduction_pct": 50.0,  # avoided = 25_000, ROI = 25_000/5_000 = 5.0
    })
    assert t["roi"] == pytest.approx(5.0)


def test_create_treatment_invalid_type_defaults(engine):
    s = engine.create_scenario("org1", {"name": "T"})
    t = engine.create_treatment("org1", s["scenario_id"], {"treatment_type": "voodoo"})
    assert t["treatment_type"] == "mitigate"


def test_list_treatments_by_scenario(engine):
    s1 = engine.create_scenario("org1", {"name": "Scen1"})
    s2 = engine.create_scenario("org1", {"name": "Scen2"})
    engine.create_treatment("org1", s1["scenario_id"], {"description": "T1"})
    engine.create_treatment("org1", s2["scenario_id"], {"description": "T2"})
    results = engine.list_treatments("org1", s1["scenario_id"])
    assert len(results) == 1
    assert results[0]["scenario_id"] == s1["scenario_id"]


def test_list_treatments_all(engine):
    s = engine.create_scenario("org1", {"name": "All Treatments"})
    engine.create_treatment("org1", s["scenario_id"], {"description": "A"})
    engine.create_treatment("org1", s["scenario_id"], {"description": "B"})
    results = engine.list_treatments("org1")
    assert len(results) >= 2


# ---------------------------------------------------------------------------
# Financial Impacts
# ---------------------------------------------------------------------------

def test_record_financial_impact(engine):
    fi = engine.record_financial_impact("org1", {
        "incident_type": "ransomware",
        "direct_cost": 100_000.0,
        "regulatory_fines": 50_000.0,
        "remediation_cost": 25_000.0,
        "business_disruption_cost": 75_000.0,
        "reputational_cost": 30_000.0,
    })
    assert fi["impact_id"]
    assert fi["total_loss"] == pytest.approx(280_000.0)
    assert fi["incident_type"] == "ransomware"


def test_financial_impact_total_loss_sum(engine):
    fi = engine.record_financial_impact("org1", {
        "incident_type": "data_breach",
        "direct_cost": 10_000.0,
        "regulatory_fines": 20_000.0,
        "remediation_cost": 30_000.0,
        "business_disruption_cost": 0.0,
        "reputational_cost": 0.0,
    })
    assert fi["total_loss"] == pytest.approx(60_000.0)


def test_list_financial_impacts(engine):
    engine.record_financial_impact("org1", {"incident_type": "phishing", "direct_cost": 5_000.0})
    engine.record_financial_impact("org1", {"incident_type": "malware", "direct_cost": 8_000.0})
    results = engine.list_financial_impacts("org1")
    assert len(results) >= 2


def test_list_financial_impacts_fiscal_year_filter(engine):
    engine.record_financial_impact("org1", {"incident_type": "X", "fiscal_year": 2025})
    engine.record_financial_impact("org1", {"incident_type": "Y", "fiscal_year": 2026})
    results_2025 = engine.list_financial_impacts("org1", fiscal_year=2025)
    assert all(r["fiscal_year"] == 2025 for r in results_2025)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_risk_stats_empty(engine):
    stats = engine.get_risk_stats("org_new")
    assert stats["total_scenarios"] == 0
    assert stats["total_ale"] == 0.0


def test_get_risk_stats_with_data(engine):
    engine.create_scenario("org1", {
        "name": "S1", "likelihood_pct": 50.0,
        "minimum_loss": 0.0, "maximum_loss": 200_000.0,
    })
    engine.create_scenario("org1", {
        "name": "S2", "likelihood_pct": 30.0,
        "minimum_loss": 0.0, "maximum_loss": 100_000.0,
    })
    stats = engine.get_risk_stats("org1")
    assert stats["total_scenarios"] == 2
    assert stats["total_ale"] > 0
    assert stats["highest_risk_scenario"] is not None


def test_get_risk_stats_treatment_count(engine):
    s = engine.create_scenario("org1", {"name": "Stats Scen"})
    engine.create_treatment("org1", s["scenario_id"], {"cost": 1_000.0, "risk_reduction_pct": 10.0})
    engine.create_treatment("org1", s["scenario_id"], {"cost": 2_000.0, "risk_reduction_pct": 20.0})
    stats = engine.get_risk_stats("org1")
    assert stats["total_treatments"] >= 2
