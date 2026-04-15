"""Tests for RiskScenarioEngine — 35+ tests covering all methods."""
from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.risk_scenario_engine import (
    RiskScenarioEngine,
    _compute_risk_level,
    _clamp,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return RiskScenarioEngine(db_path=str(tmp_path / "test.db"))


ORG = "org-rs-test"
ORG2 = "org-rs-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scenario(engine, org=ORG, name="Ransomware Attack", threat_category="ransomware",
                   likelihood=7.0, impact=8.0, owner="ciso"):
    return engine.create_scenario(org, name, threat_category, "Test scenario",
                                  likelihood, impact, owner)


def _make_mitigation(engine, sid, org=ORG, name="Endpoint Protection",
                     mtype="technical", effectiveness=0.5, cost=10000.0):
    return engine.add_mitigation(sid, org, name, mitigation_type=mtype,
                                 effectiveness=effectiveness, cost_estimate=cost)


# ---------------------------------------------------------------------------
# _compute_risk_level unit tests
# ---------------------------------------------------------------------------

def test_risk_level_critical_boundary():
    assert _compute_risk_level(70.0) == "critical"


def test_risk_level_critical_above():
    assert _compute_risk_level(100.0) == "critical"


def test_risk_level_high_boundary():
    assert _compute_risk_level(40.0) == "high"


def test_risk_level_high_upper():
    assert _compute_risk_level(69.9) == "high"


def test_risk_level_medium_boundary():
    assert _compute_risk_level(20.0) == "medium"


def test_risk_level_medium_upper():
    assert _compute_risk_level(39.9) == "medium"


def test_risk_level_low_below():
    assert _compute_risk_level(19.9) == "low"


def test_risk_level_low_zero():
    assert _compute_risk_level(0.0) == "low"


# ---------------------------------------------------------------------------
# _clamp unit tests
# ---------------------------------------------------------------------------

def test_clamp_within():
    assert _clamp(5.0, 0.0, 10.0) == 5.0


def test_clamp_low():
    assert _clamp(-1.0, 0.0, 10.0) == 0.0


def test_clamp_high():
    assert _clamp(11.0, 0.0, 10.0) == 10.0


# ---------------------------------------------------------------------------
# Scenario creation
# ---------------------------------------------------------------------------

def test_create_scenario_basic(engine):
    s = _make_scenario(engine)
    assert s["scenario_name"] == "Ransomware Attack"
    assert s["threat_category"] == "ransomware"
    assert s["likelihood"] == 7.0
    assert s["impact"] == 8.0
    assert s["inherent_risk"] == pytest.approx(56.0)
    assert s["residual_risk"] == pytest.approx(56.0)
    assert s["risk_level"] == "high"
    assert s["status"] == "active"
    assert s["org_id"] == ORG


def test_create_scenario_all_threat_categories(engine):
    cats = ["ransomware", "data-breach", "insider-threat", "supply-chain",
            "ddos", "phishing", "zero-day", "compliance"]
    for cat in cats:
        s = engine.create_scenario(ORG, f"S-{cat}", cat, "desc", 5.0, 5.0)
        assert s["threat_category"] == cat


def test_create_scenario_invalid_category(engine):
    with pytest.raises(ValueError, match="threat_category"):
        engine.create_scenario(ORG, "Bad", "unknown-threat", "desc", 5.0, 5.0)


def test_create_scenario_likelihood_clamped(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 15.0, 5.0)
    assert s["likelihood"] == 10.0


def test_create_scenario_impact_clamped(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 5.0, -3.0)
    assert s["impact"] == 0.0


def test_create_scenario_inherent_risk_computed(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 5.0, 5.0)
    assert s["inherent_risk"] == pytest.approx(25.0)


def test_create_scenario_risk_level_critical(engine):
    # 9 * 9 = 81 → critical
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 9.0, 9.0)
    assert s["risk_level"] == "critical"


def test_create_scenario_risk_level_medium(engine):
    # 4 * 5 = 20 → medium
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 4.0, 5.0)
    assert s["risk_level"] == "medium"


def test_create_scenario_risk_level_low(engine):
    # 1 * 1 = 1 → low
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 1.0, 1.0)
    assert s["risk_level"] == "low"


# ---------------------------------------------------------------------------
# Mitigations
# ---------------------------------------------------------------------------

def test_add_mitigation_basic(engine):
    s = _make_scenario(engine)
    m = _make_mitigation(engine, s["id"])
    assert m["scenario_id"] == s["id"]
    assert m["effectiveness"] == 0.5
    assert m["implemented"] == 0


def test_add_mitigation_all_types(engine):
    s = _make_scenario(engine)
    for mtype in ["technical", "administrative", "physical", "detective", "preventive", "corrective"]:
        m = engine.add_mitigation(s["id"], ORG, f"M-{mtype}", mitigation_type=mtype, effectiveness=0.1)
        assert m["mitigation_type"] == mtype


def test_add_mitigation_invalid_type(engine):
    s = _make_scenario(engine)
    with pytest.raises(ValueError, match="mitigation_type"):
        engine.add_mitigation(s["id"], ORG, "Bad", mitigation_type="magic")


def test_add_mitigation_effectiveness_clamped(engine):
    s = _make_scenario(engine)
    m = engine.add_mitigation(s["id"], ORG, "M", effectiveness=1.5)
    assert m["effectiveness"] == 1.0


def test_add_mitigation_effectiveness_clamped_low(engine):
    s = _make_scenario(engine)
    m = engine.add_mitigation(s["id"], ORG, "M", effectiveness=-0.1)
    assert m["effectiveness"] == 0.0


def test_implement_mitigation_reduces_residual(engine):
    # 5*5=25 inherent; implement 0.5 eff → residual = 25*(1-0.5) = 12.5
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 5.0, 5.0)
    m = engine.add_mitigation(s["id"], ORG, "M", effectiveness=0.5)
    result = engine.implement_mitigation(m["id"], s["id"], ORG)
    assert result["implemented"] == 1
    updated = engine.get_scenario(s["id"], ORG)
    assert updated["residual_risk"] == pytest.approx(12.5)


def test_implement_mitigation_caps_at_90_pct(engine):
    """Total implemented effectiveness capped at 0.9."""
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 10.0, 10.0)
    # inherent = 100
    m1 = engine.add_mitigation(s["id"], ORG, "M1", effectiveness=0.6)
    m2 = engine.add_mitigation(s["id"], ORG, "M2", effectiveness=0.6)
    engine.implement_mitigation(m1["id"], s["id"], ORG)
    engine.implement_mitigation(m2["id"], s["id"], ORG)
    updated = engine.get_scenario(s["id"], ORG)
    # 0.6+0.6=1.2 → capped at 0.9 → residual=100*(1-0.9)=10.0
    assert updated["residual_risk"] == pytest.approx(10.0)


def test_implement_mitigation_not_found(engine):
    s = _make_scenario(engine)
    result = engine.implement_mitigation("bad-id", s["id"], ORG)
    assert result is None


# ---------------------------------------------------------------------------
# Reviews
# ---------------------------------------------------------------------------

def test_review_scenario_basic(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 5.0, 5.0)
    review = engine.review_scenario(s["id"], ORG, "alice", 1.0, 0.0, "Increased likelihood")
    assert review["reviewer"] == "alice"
    assert review["likelihood_adjustment"] == 1.0


def test_review_scenario_updates_inherent_risk(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 5.0, 5.0)
    engine.review_scenario(s["id"], ORG, "alice", 1.0, 1.0, "Both up")
    updated = engine.get_scenario(s["id"], ORG)
    # new likelihood=6, impact=6 → inherent=36
    assert updated["inherent_risk"] == pytest.approx(36.0)


def test_review_scenario_clamps_likelihood(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 9.0, 5.0)
    engine.review_scenario(s["id"], ORG, "alice", 5.0, 0.0)
    updated = engine.get_scenario(s["id"], ORG)
    assert updated["likelihood"] == 10.0  # clamped


def test_review_scenario_negative_adjustment(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 8.0, 8.0)
    engine.review_scenario(s["id"], ORG, "bob", -2.0, -2.0, "Reduced")
    updated = engine.get_scenario(s["id"], ORG)
    assert updated["likelihood"] == 6.0
    assert updated["impact"] == 6.0
    assert updated["inherent_risk"] == pytest.approx(36.0)


def test_review_sets_reviewed_at(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 5.0, 5.0)
    assert s["reviewed_at"] is None
    engine.review_scenario(s["id"], ORG, "alice", 0.0, 0.0)
    updated = engine.get_scenario(s["id"], ORG)
    assert updated["reviewed_at"] is not None


# ---------------------------------------------------------------------------
# get_scenario / list_scenarios
# ---------------------------------------------------------------------------

def test_get_scenario_includes_mitigations_and_reviews(engine):
    s = _make_scenario(engine)
    _make_mitigation(engine, s["id"])
    engine.review_scenario(s["id"], ORG, "alice", 0.0, 0.0)
    result = engine.get_scenario(s["id"], ORG)
    assert len(result["mitigations"]) == 1
    assert len(result["reviews"]) == 1


def test_get_scenario_not_found(engine):
    assert engine.get_scenario("bad-id", ORG) is None


def test_list_scenarios_all(engine):
    _make_scenario(engine, name="S1")
    _make_scenario(engine, name="S2")
    results = engine.list_scenarios(ORG)
    assert len(results) == 2


def test_list_scenarios_filter_risk_level(engine):
    engine.create_scenario(ORG, "Low", "ransomware", "desc", 1.0, 1.0)
    engine.create_scenario(ORG, "Critical", "ransomware", "desc", 9.0, 9.0)
    lows = engine.list_scenarios(ORG, risk_level="low")
    crits = engine.list_scenarios(ORG, risk_level="critical")
    assert len(lows) == 1
    assert len(crits) == 1


def test_list_scenarios_filter_threat_category(engine):
    engine.create_scenario(ORG, "R", "ransomware", "desc", 5.0, 5.0)
    engine.create_scenario(ORG, "P", "phishing", "desc", 5.0, 5.0)
    results = engine.list_scenarios(ORG, threat_category="phishing")
    assert len(results) == 1
    assert results[0]["threat_category"] == "phishing"


def test_org_isolation(engine):
    engine.create_scenario(ORG, "S1", "ransomware", "desc", 5.0, 5.0)
    engine.create_scenario(ORG2, "S2", "ransomware", "desc", 5.0, 5.0)
    assert len(engine.list_scenarios(ORG)) == 1
    assert len(engine.list_scenarios(ORG2)) == 1


# ---------------------------------------------------------------------------
# Top risks
# ---------------------------------------------------------------------------

def test_get_top_risks_ordered(engine):
    engine.create_scenario(ORG, "Low", "ransomware", "desc", 1.0, 1.0)
    engine.create_scenario(ORG, "High", "ransomware", "desc", 9.0, 9.0)
    engine.create_scenario(ORG, "Mid", "ransomware", "desc", 5.0, 5.0)
    top = engine.get_top_risks(ORG, limit=3)
    assert top[0]["scenario_name"] == "High"
    assert top[-1]["scenario_name"] == "Low"


def test_get_top_risks_limit(engine):
    for i in range(5):
        engine.create_scenario(ORG, f"S{i}", "ransomware", "desc", float(i+1), float(i+1))
    top = engine.get_top_risks(ORG, limit=3)
    assert len(top) == 3


# ---------------------------------------------------------------------------
# Risk reduction summary
# ---------------------------------------------------------------------------

def test_get_risk_reduction_summary(engine):
    s = engine.create_scenario(ORG, "S", "ransomware", "desc", 10.0, 10.0)
    m = engine.add_mitigation(s["id"], ORG, "M", effectiveness=0.5)
    engine.implement_mitigation(m["id"], s["id"], ORG)
    summary = engine.get_risk_reduction_summary(ORG)
    assert len(summary) == 1
    entry = summary[0]
    assert entry["inherent_risk"] == pytest.approx(100.0)
    assert entry["residual_risk"] == pytest.approx(50.0)
    assert entry["reduction_pct"] == pytest.approx(50.0)


def test_get_risk_reduction_zero_inherent(engine):
    engine.create_scenario(ORG, "S", "ransomware", "desc", 0.0, 0.0)
    summary = engine.get_risk_reduction_summary(ORG)
    assert summary[0]["reduction_pct"] == 0.0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_scenario_stats_empty(engine):
    stats = engine.get_scenario_stats(ORG)
    assert stats["total_scenarios"] == 0
    assert stats["total_mitigations"] == 0
    assert stats["implemented_mitigations"] == 0


def test_get_scenario_stats_counts(engine):
    engine.create_scenario(ORG, "S1", "ransomware", "desc", 1.0, 1.0)
    engine.create_scenario(ORG, "S2", "ransomware", "desc", 9.0, 9.0)
    stats = engine.get_scenario_stats(ORG)
    assert stats["total_scenarios"] == 2
    assert "low" in stats["by_risk_level"]
    assert "critical" in stats["by_risk_level"]


def test_get_scenario_stats_mitigations(engine):
    s = _make_scenario(engine)
    m = _make_mitigation(engine, s["id"])
    _make_mitigation(engine, s["id"], name="M2")
    engine.implement_mitigation(m["id"], s["id"], ORG)
    stats = engine.get_scenario_stats(ORG)
    assert stats["total_mitigations"] == 2
    assert stats["implemented_mitigations"] == 1


def test_get_scenario_stats_avg_risks(engine):
    engine.create_scenario(ORG, "S1", "ransomware", "desc", 5.0, 4.0)  # inherent=20
    engine.create_scenario(ORG, "S2", "ransomware", "desc", 5.0, 6.0)  # inherent=30
    stats = engine.get_scenario_stats(ORG)
    assert stats["avg_inherent_risk"] == pytest.approx(25.0)
