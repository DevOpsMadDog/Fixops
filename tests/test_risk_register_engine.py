"""Tests for RiskRegisterEngine — 35 tests covering all methods."""
from __future__ import annotations

import pytest

from core.risk_register_engine import (
    RiskRegisterEngine,
    _compute_risk_level,
    _LIKELIHOOD_VALUES,
    _IMPACT_VALUES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_risk_register_engine.db")


@pytest.fixture
def engine(db_path):
    return RiskRegisterEngine(db_path=db_path)


ORG = "org-rr-test"
ORG2 = "org-rr-other"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_risk(engine, org=ORG, **kwargs):
    defaults = {
        "name": "Test Risk",
        "risk_category": "operational",
        "likelihood": "possible",
        "impact": "moderate",
    }
    defaults.update(kwargs)
    return engine.create_risk(org, defaults)


def _make_treatment(engine, risk_id, org=ORG, **kwargs):
    defaults = {
        "treatment_type": "mitigate",
        "description": "Apply patch",
        "cost_estimate": 1000.0,
        "timeline_days": 30,
        "owner": "security-team",
    }
    defaults.update(kwargs)
    return engine.add_risk_treatment(org, risk_id, defaults)


# ---------------------------------------------------------------------------
# _compute_risk_level (unit tests)
# ---------------------------------------------------------------------------

def test_risk_level_critical():
    assert _compute_risk_level(25) == "critical"


def test_risk_level_critical_boundary():
    assert _compute_risk_level(20) == "critical"


def test_risk_level_high():
    assert _compute_risk_level(12) == "high"


def test_risk_level_high_upper():
    assert _compute_risk_level(19) == "high"


def test_risk_level_medium():
    assert _compute_risk_level(6) == "medium"


def test_risk_level_medium_upper():
    assert _compute_risk_level(11) == "medium"


def test_risk_level_low():
    assert _compute_risk_level(5) == "low"


def test_risk_level_low_zero():
    assert _compute_risk_level(0) == "low"


# ---------------------------------------------------------------------------
# Risk score computation
# ---------------------------------------------------------------------------

def test_risk_score_certain_catastrophic(engine):
    """certain=5 * catastrophic=5 = 25 → critical"""
    risk = _make_risk(engine, likelihood="certain", impact="catastrophic")
    assert risk["risk_score"] == 25
    assert risk["risk_level"] == "critical"


def test_risk_score_unlikely_minor(engine):
    """unlikely=2 * minor=2 = 4 → low"""
    risk = _make_risk(engine, likelihood="unlikely", impact="minor")
    assert risk["risk_score"] == 4
    assert risk["risk_level"] == "low"


def test_risk_score_likely_major(engine):
    """likely=4 * major=4 = 16 → high (≥12 but <20)"""
    risk = _make_risk(engine, likelihood="likely", impact="major")
    assert risk["risk_score"] == 16
    assert risk["risk_level"] == "high"


def test_risk_score_possible_moderate(engine):
    """possible=3 * moderate=3 = 9 → medium"""
    risk = _make_risk(engine, likelihood="possible", impact="moderate")
    assert risk["risk_score"] == 9
    assert risk["risk_level"] == "medium"


def test_risk_score_rare_negligible(engine):
    """rare=1 * negligible=1 = 1 → low"""
    risk = _make_risk(engine, likelihood="rare", impact="negligible")
    assert risk["risk_score"] == 1
    assert risk["risk_level"] == "low"


def test_risk_score_likely_moderate(engine):
    """likely=4 * moderate=3 = 12 → high"""
    risk = _make_risk(engine, likelihood="likely", impact="moderate")
    assert risk["risk_score"] == 12
    assert risk["risk_level"] == "high"


# ---------------------------------------------------------------------------
# create_risk — validation
# ---------------------------------------------------------------------------

def test_create_risk_requires_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_risk(ORG, {"name": ""})


def test_create_risk_invalid_category(engine):
    with pytest.raises(ValueError, match="risk_category"):
        engine.create_risk(ORG, {"name": "R", "risk_category": "unknown"})


def test_create_risk_invalid_likelihood(engine):
    with pytest.raises(ValueError, match="likelihood"):
        engine.create_risk(ORG, {"name": "R", "likelihood": "always"})


def test_create_risk_invalid_impact(engine):
    with pytest.raises(ValueError, match="impact"):
        engine.create_risk(ORG, {"name": "R", "impact": "massive"})


def test_create_risk_default_status_identified(engine):
    risk = _make_risk(engine)
    assert risk["status"] == "identified"


def test_create_risk_has_timestamps(engine):
    risk = _make_risk(engine)
    assert risk["created_at"]
    assert risk["updated_at"]


def test_create_risk_all_categories(engine):
    categories = ["strategic", "operational", "compliance", "technical",
                  "financial", "reputational", "third_party"]
    for cat in categories:
        r = _make_risk(engine, name=f"Risk {cat}", risk_category=cat)
        assert r["risk_category"] == cat


# ---------------------------------------------------------------------------
# list_risks / get_risk
# ---------------------------------------------------------------------------

def test_list_risks_empty(engine):
    assert engine.list_risks(ORG) == []


def test_list_risks_returns_created(engine):
    _make_risk(engine, name="Alpha")
    _make_risk(engine, name="Beta")
    risks = engine.list_risks(ORG)
    assert len(risks) == 2


def test_list_risks_filter_category(engine):
    _make_risk(engine, name="R1", risk_category="technical")
    _make_risk(engine, name="R2", risk_category="financial")
    result = engine.list_risks(ORG, risk_category="technical")
    assert len(result) == 1
    assert result[0]["risk_category"] == "technical"


def test_list_risks_filter_level(engine):
    _make_risk(engine, likelihood="certain", impact="catastrophic")  # critical
    _make_risk(engine, likelihood="rare", impact="negligible")       # low
    result = engine.list_risks(ORG, risk_level="critical")
    assert len(result) == 1
    assert result[0]["risk_level"] == "critical"


def test_list_risks_filter_status(engine):
    r = _make_risk(engine, name="To close")
    engine.update_risk_status(ORG, r["id"], "closed")
    open_risks = engine.list_risks(ORG, status="identified")
    closed_risks = engine.list_risks(ORG, status="closed")
    assert len(open_risks) == 0
    assert len(closed_risks) == 1


def test_get_risk_found(engine):
    created = _make_risk(engine)
    fetched = engine.get_risk(ORG, created["id"])
    assert fetched is not None
    assert fetched["id"] == created["id"]


def test_get_risk_not_found(engine):
    assert engine.get_risk(ORG, "nonexistent-id") is None


# ---------------------------------------------------------------------------
# org_id isolation
# ---------------------------------------------------------------------------

def test_org_isolation_list(engine):
    _make_risk(engine, org=ORG, name="Org1 Risk")
    _make_risk(engine, org=ORG2, name="Org2 Risk")
    assert len(engine.list_risks(ORG)) == 1
    assert len(engine.list_risks(ORG2)) == 1


def test_org_isolation_get(engine):
    risk = _make_risk(engine, org=ORG)
    assert engine.get_risk(ORG2, risk["id"]) is None


# ---------------------------------------------------------------------------
# update_risk_status
# ---------------------------------------------------------------------------

def test_update_risk_status_valid(engine):
    risk = _make_risk(engine)
    updated = engine.update_risk_status(ORG, risk["id"], "assessed")
    assert updated["status"] == "assessed"


def test_update_risk_status_with_treatment_plan(engine):
    risk = _make_risk(engine)
    updated = engine.update_risk_status(ORG, risk["id"], "treated", treatment_plan="Apply MFA")
    assert updated["treatment_plan"] == "Apply MFA"


def test_update_risk_status_invalid(engine):
    risk = _make_risk(engine)
    with pytest.raises(ValueError, match="status"):
        engine.update_risk_status(ORG, risk["id"], "unknown_status")


def test_update_risk_status_all_valid_statuses(engine):
    for status in ["identified", "assessed", "treated", "accepted", "closed"]:
        risk = _make_risk(engine, name=f"Risk-{status}")
        updated = engine.update_risk_status(ORG, risk["id"], status)
        assert updated["status"] == status


def test_update_risk_status_returns_none_for_missing(engine):
    result = engine.update_risk_status(ORG, "bad-id", "assessed")
    assert result is None


# ---------------------------------------------------------------------------
# add_risk_treatment / list_treatments
# ---------------------------------------------------------------------------

def test_add_treatment_returns_record(engine):
    risk = _make_risk(engine)
    t = _make_treatment(engine, risk["id"])
    assert t["risk_id"] == risk["id"]
    assert t["treatment_type"] == "mitigate"
    assert t["status"] == "planned"


def test_add_treatment_invalid_type(engine):
    risk = _make_risk(engine)
    with pytest.raises(ValueError, match="treatment_type"):
        engine.add_risk_treatment(ORG, risk["id"], {"treatment_type": "ignore"})


def test_add_treatment_all_valid_types(engine):
    risk = _make_risk(engine)
    for ttype in ["mitigate", "transfer", "accept", "avoid"]:
        t = _make_treatment(engine, risk["id"], treatment_type=ttype)
        assert t["treatment_type"] == ttype


def test_list_treatments_all(engine):
    r1 = _make_risk(engine, name="R1")
    r2 = _make_risk(engine, name="R2")
    _make_treatment(engine, r1["id"])
    _make_treatment(engine, r2["id"])
    all_treatments = engine.list_treatments(ORG)
    assert len(all_treatments) == 2


def test_list_treatments_filtered_by_risk(engine):
    r1 = _make_risk(engine, name="R1")
    r2 = _make_risk(engine, name="R2")
    _make_treatment(engine, r1["id"])
    _make_treatment(engine, r2["id"])
    result = engine.list_treatments(ORG, risk_id=r1["id"])
    assert len(result) == 1
    assert result[0]["risk_id"] == r1["id"]


def test_list_treatments_org_isolation(engine):
    r1 = _make_risk(engine, org=ORG)
    r2 = _make_risk(engine, org=ORG2)
    _make_treatment(engine, r1["id"], org=ORG)
    _make_treatment(engine, r2["id"], org=ORG2)
    assert len(engine.list_treatments(ORG)) == 1
    assert len(engine.list_treatments(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_risk_stats
# ---------------------------------------------------------------------------

def test_stats_empty(engine):
    stats = engine.get_risk_stats(ORG)
    assert stats["total_risks"] == 0
    assert stats["critical_risks"] == 0
    assert stats["high_risks"] == 0
    assert stats["open_risks"] == 0
    assert stats["avg_risk_score"] is None
    assert stats["top_risk"] is None


def test_stats_with_risks(engine):
    _make_risk(engine, likelihood="certain", impact="catastrophic")  # critical, score=25
    _make_risk(engine, likelihood="likely", impact="moderate")       # high, score=12 (4*3=12, ≥12)
    _make_risk(engine, likelihood="rare", impact="negligible")       # low, score=1
    stats = engine.get_risk_stats(ORG)
    assert stats["total_risks"] == 3
    assert stats["critical_risks"] == 1
    assert stats["high_risks"] == 1
    assert stats["avg_risk_score"] is not None


def test_stats_open_risks_excludes_closed_accepted(engine):
    r1 = _make_risk(engine, name="Open")
    r2 = _make_risk(engine, name="Closed")
    r3 = _make_risk(engine, name="Accepted")
    engine.update_risk_status(ORG, r2["id"], "closed")
    engine.update_risk_status(ORG, r3["id"], "accepted")
    stats = engine.get_risk_stats(ORG)
    assert stats["open_risks"] == 1


def test_stats_by_category(engine):
    _make_risk(engine, risk_category="technical")
    _make_risk(engine, risk_category="technical")
    _make_risk(engine, risk_category="financial")
    stats = engine.get_risk_stats(ORG)
    assert stats["by_category"]["technical"] == 2
    assert stats["by_category"]["financial"] == 1


def test_stats_top_risk(engine):
    _make_risk(engine, name="Small", likelihood="rare", impact="negligible")    # score=1
    _make_risk(engine, name="Big", likelihood="certain", impact="catastrophic")  # score=25
    stats = engine.get_risk_stats(ORG)
    assert stats["top_risk"]["name"] == "Big"
    assert stats["top_risk"]["score"] == 25


def test_stats_org_isolation(engine):
    _make_risk(engine, org=ORG)
    _make_risk(engine, org=ORG2)
    stats1 = engine.get_risk_stats(ORG)
    stats2 = engine.get_risk_stats(ORG2)
    assert stats1["total_risks"] == 1
    assert stats2["total_risks"] == 1
