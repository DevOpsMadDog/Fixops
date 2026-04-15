"""Tests for TPRMExchangeEngine — 38+ tests covering all methods."""
from __future__ import annotations

import json
import time
import pytest

from core.tprm_exchange_engine import TPRMExchangeEngine, _score_to_tier, _CRITICALITY_TO_TIER


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_tprm_exchange.db")


@pytest.fixture
def engine(db_path):
    return TPRMExchangeEngine(db_path=db_path)


ORG = "org-tprm-test"
ORG2 = "org-tprm-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vendor(engine, org=ORG, **kwargs):
    defaults = dict(
        vendor_name="Acme Corp",
        vendor_category="saas",
        criticality="medium",
        data_shared=["PII", "financial"],
        contract_start="2024-01-01",
        contract_end="2025-01-01",
        annual_spend=50000.0,
        primary_contact="vendor@acme.com",
    )
    defaults.update(kwargs)
    return engine.register_vendor(org_id=org, **defaults)


def _make_assessment(engine, vendor_id, org=ORG, **kwargs):
    defaults = dict(
        assessment_type="annual",
        assessor="security-team",
        due_date="2030-12-31",
    )
    defaults.update(kwargs)
    return engine.create_assessment(vendor_id=vendor_id, org_id=org, **defaults)


def _make_incident(engine, vendor_id, org=ORG, **kwargs):
    defaults = dict(
        incident_type="service_outage",
        severity="medium",
        description="Service down",
        impact="Minor disruption",
    )
    defaults.update(kwargs)
    return engine.report_incident(vendor_id=vendor_id, org_id=org, **defaults)


# ---------------------------------------------------------------------------
# _score_to_tier (unit tests)
# ---------------------------------------------------------------------------

def test_score_to_tier_below_40_is_tier1():
    assert _score_to_tier(0.0) == "tier-1"
    assert _score_to_tier(39.9) == "tier-1"


def test_score_to_tier_40_to_59_is_tier2():
    assert _score_to_tier(40.0) == "tier-2"
    assert _score_to_tier(59.9) == "tier-2"


def test_score_to_tier_60_to_79_is_tier3():
    assert _score_to_tier(60.0) == "tier-3"
    assert _score_to_tier(79.9) == "tier-3"


def test_score_to_tier_80_plus_is_tier4():
    assert _score_to_tier(80.0) == "tier-4"
    assert _score_to_tier(100.0) == "tier-4"


# ---------------------------------------------------------------------------
# _CRITICALITY_TO_TIER mapping
# ---------------------------------------------------------------------------

def test_criticality_map_critical_is_tier1():
    assert _CRITICALITY_TO_TIER["critical"] == "tier-1"


def test_criticality_map_high_is_tier2():
    assert _CRITICALITY_TO_TIER["high"] == "tier-2"


def test_criticality_map_medium_is_tier3():
    assert _CRITICALITY_TO_TIER["medium"] == "tier-3"


def test_criticality_map_low_is_tier4():
    assert _CRITICALITY_TO_TIER["low"] == "tier-4"


# ---------------------------------------------------------------------------
# register_vendor
# ---------------------------------------------------------------------------

def test_register_vendor_returns_dict(engine):
    v = _make_vendor(engine)
    assert v["id"]
    assert v["vendor_name"] == "Acme Corp"
    assert v["org_id"] == ORG


def test_register_vendor_criticality_tier_mapping(engine):
    v_crit = _make_vendor(engine, criticality="critical", vendor_name="V1")
    v_high = _make_vendor(engine, criticality="high", vendor_name="V2")
    v_med = _make_vendor(engine, criticality="medium", vendor_name="V3")
    v_low = _make_vendor(engine, criticality="low", vendor_name="V4")
    assert v_crit["risk_tier"] == "tier-1"
    assert v_high["risk_tier"] == "tier-2"
    assert v_med["risk_tier"] == "tier-3"
    assert v_low["risk_tier"] == "tier-4"


def test_register_vendor_data_shared_stored_as_list(engine):
    v = _make_vendor(engine, data_shared=["PII", "financial"])
    assert isinstance(v["data_shared"], list)
    assert "PII" in v["data_shared"]


def test_register_vendor_risk_score_starts_at_zero(engine):
    v = _make_vendor(engine)
    assert v["risk_score"] == 0.0


def test_register_vendor_status_active(engine):
    v = _make_vendor(engine)
    assert v["status"] == "active"


def test_register_vendor_invalid_category_raises(engine):
    with pytest.raises(ValueError, match="Invalid vendor_category"):
        _make_vendor(engine, vendor_category="unknown")


def test_register_vendor_invalid_criticality_raises(engine):
    with pytest.raises(ValueError, match="Invalid criticality"):
        _make_vendor(engine, criticality="extreme")


# ---------------------------------------------------------------------------
# create_assessment
# ---------------------------------------------------------------------------

def test_create_assessment_returns_dict(engine):
    v = _make_vendor(engine)
    a = _make_assessment(engine, v["id"])
    assert a["id"]
    assert a["vendor_id"] == v["id"]
    assert a["org_id"] == ORG


def test_create_assessment_status_in_progress(engine):
    v = _make_vendor(engine)
    a = _make_assessment(engine, v["id"])
    assert a["status"] == "in_progress"


def test_create_assessment_invalid_type_raises(engine):
    v = _make_vendor(engine)
    with pytest.raises(ValueError, match="Invalid assessment_type"):
        engine.create_assessment(v["id"], ORG, assessment_type="quarterly")


def test_create_assessment_nonexistent_vendor_raises(engine):
    with pytest.raises(ValueError):
        engine.create_assessment("no-such-vendor", ORG, "annual", "assessor")


# ---------------------------------------------------------------------------
# complete_assessment
# ---------------------------------------------------------------------------

def test_complete_assessment_sets_status_completed(engine):
    v = _make_vendor(engine)
    a = _make_assessment(engine, v["id"])
    result = engine.complete_assessment(a["id"], ORG, score=75.0)
    assert result["status"] == "completed"


def test_complete_assessment_updates_vendor_risk_score(engine):
    v = _make_vendor(engine)
    a = _make_assessment(engine, v["id"])
    engine.complete_assessment(a["id"], ORG, score=55.0)
    detail = engine.get_vendor_detail(v["id"], ORG)
    assert detail["risk_score"] == pytest.approx(55.0)


def test_complete_assessment_retiers_vendor_score_below_40(engine):
    v = _make_vendor(engine, criticality="low")  # starts tier-4
    a = _make_assessment(engine, v["id"])
    engine.complete_assessment(a["id"], ORG, score=30.0)
    detail = engine.get_vendor_detail(v["id"], ORG)
    assert detail["risk_tier"] == "tier-1"


def test_complete_assessment_retiers_vendor_score_40_to_59(engine):
    v = _make_vendor(engine, criticality="low")
    a = _make_assessment(engine, v["id"])
    engine.complete_assessment(a["id"], ORG, score=50.0)
    detail = engine.get_vendor_detail(v["id"], ORG)
    assert detail["risk_tier"] == "tier-2"


def test_complete_assessment_retiers_vendor_score_60_to_79(engine):
    v = _make_vendor(engine, criticality="low")
    a = _make_assessment(engine, v["id"])
    engine.complete_assessment(a["id"], ORG, score=70.0)
    detail = engine.get_vendor_detail(v["id"], ORG)
    assert detail["risk_tier"] == "tier-3"


def test_complete_assessment_retiers_vendor_score_80_plus(engine):
    v = _make_vendor(engine, criticality="critical")  # starts tier-1
    a = _make_assessment(engine, v["id"])
    engine.complete_assessment(a["id"], ORG, score=90.0)
    detail = engine.get_vendor_detail(v["id"], ORG)
    assert detail["risk_tier"] == "tier-4"


def test_complete_assessment_wrong_org_raises(engine):
    v = _make_vendor(engine)
    a = _make_assessment(engine, v["id"])
    with pytest.raises(ValueError):
        engine.complete_assessment(a["id"], ORG2, score=80.0)


# ---------------------------------------------------------------------------
# report_incident
# ---------------------------------------------------------------------------

def test_report_incident_returns_dict(engine):
    v = _make_vendor(engine)
    inc = _make_incident(engine, v["id"])
    assert inc["id"]
    assert inc["vendor_id"] == v["id"]
    assert inc["status"] == "open"


def test_report_incident_invalid_type_raises(engine):
    v = _make_vendor(engine)
    with pytest.raises(ValueError, match="Invalid incident_type"):
        engine.report_incident(v["id"], ORG, incident_type="alien_attack")


def test_report_incident_nonexistent_vendor_raises(engine):
    with pytest.raises(ValueError):
        engine.report_incident("no-such-vendor", ORG, incident_type="data_breach")


# ---------------------------------------------------------------------------
# resolve_incident
# ---------------------------------------------------------------------------

def test_resolve_incident_sets_status_resolved(engine):
    v = _make_vendor(engine)
    inc = _make_incident(engine, v["id"])
    result = engine.resolve_incident(inc["id"], ORG)
    assert result["status"] == "resolved"
    assert result["resolved_at"] != ""


def test_resolve_incident_wrong_org_raises(engine):
    v = _make_vendor(engine)
    inc = _make_incident(engine, v["id"])
    with pytest.raises(ValueError):
        engine.resolve_incident(inc["id"], ORG2)


# ---------------------------------------------------------------------------
# get_vendor_detail
# ---------------------------------------------------------------------------

def test_get_vendor_detail_includes_assessments_and_incidents(engine):
    v = _make_vendor(engine)
    _make_assessment(engine, v["id"])
    _make_incident(engine, v["id"])
    detail = engine.get_vendor_detail(v["id"], ORG)
    assert len(detail["assessments"]) == 1
    assert len(detail["incidents"]) == 1


def test_get_vendor_detail_wrong_org_raises(engine):
    v = _make_vendor(engine)
    with pytest.raises(ValueError):
        engine.get_vendor_detail(v["id"], ORG2)


# ---------------------------------------------------------------------------
# get_tprm_summary
# ---------------------------------------------------------------------------

def test_get_tprm_summary_total_vendors(engine):
    _make_vendor(engine, vendor_name="V1")
    _make_vendor(engine, vendor_name="V2")
    s = engine.get_tprm_summary(ORG)
    assert s["total_vendors"] == 2


def test_get_tprm_summary_by_tier(engine):
    _make_vendor(engine, vendor_name="V1", criticality="critical")
    _make_vendor(engine, vendor_name="V2", criticality="medium")
    s = engine.get_tprm_summary(ORG)
    assert s["by_tier"].get("tier-1", 0) == 1
    assert s["by_tier"].get("tier-3", 0) == 1


def test_get_tprm_summary_by_category(engine):
    _make_vendor(engine, vendor_name="V1", vendor_category="cloud_provider")
    _make_vendor(engine, vendor_name="V2", vendor_category="saas")
    s = engine.get_tprm_summary(ORG)
    assert s["by_category"].get("cloud_provider", 0) == 1
    assert s["by_category"].get("saas", 0) == 1


def test_get_tprm_summary_open_incidents(engine):
    v = _make_vendor(engine)
    _make_incident(engine, v["id"])
    s = engine.get_tprm_summary(ORG)
    assert s["open_incidents"] == 1


def test_get_tprm_summary_critical_vendors(engine):
    _make_vendor(engine, vendor_name="V1", criticality="critical")
    _make_vendor(engine, vendor_name="V2", criticality="medium")
    s = engine.get_tprm_summary(ORG)
    assert s["critical_vendors"] == 1


# ---------------------------------------------------------------------------
# get_overdue_assessments
# ---------------------------------------------------------------------------

def test_get_overdue_assessments_detects_past_due(engine):
    v = _make_vendor(engine)
    # Use a past due_date
    engine.create_assessment(v["id"], ORG, "annual", "assessor", "2020-01-01")
    overdue = engine.get_overdue_assessments(ORG)
    assert len(overdue) == 1


def test_get_overdue_assessments_excludes_future(engine):
    v = _make_vendor(engine)
    _make_assessment(engine, v["id"], due_date="2030-12-31")
    overdue = engine.get_overdue_assessments(ORG)
    assert len(overdue) == 0


def test_get_overdue_assessments_excludes_completed(engine):
    v = _make_vendor(engine)
    a = engine.create_assessment(v["id"], ORG, "annual", "assessor", "2020-01-01")
    engine.complete_assessment(a["id"], ORG, score=80.0)
    overdue = engine.get_overdue_assessments(ORG)
    assert len(overdue) == 0


# ---------------------------------------------------------------------------
# get_high_risk_vendors
# ---------------------------------------------------------------------------

def test_get_high_risk_vendors_returns_tier1_and_tier2(engine):
    _make_vendor(engine, vendor_name="V1", criticality="critical")
    _make_vendor(engine, vendor_name="V2", criticality="high")
    _make_vendor(engine, vendor_name="V3", criticality="low")
    high_risk = engine.get_high_risk_vendors(ORG)
    tiers = {v["risk_tier"] for v in high_risk}
    assert "tier-1" in tiers
    assert "tier-2" in tiers
    assert "tier-4" not in tiers


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_vendors(engine):
    _make_vendor(engine, org=ORG, vendor_name="A")
    _make_vendor(engine, org=ORG2, vendor_name="B")
    s1 = engine.get_tprm_summary(ORG)
    s2 = engine.get_tprm_summary(ORG2)
    assert s1["total_vendors"] == 1
    assert s2["total_vendors"] == 1


def test_org_isolation_assessments(engine):
    v1 = _make_vendor(engine, org=ORG)
    v2 = _make_vendor(engine, org=ORG2)
    # Create overdue assessment only in ORG
    engine.create_assessment(v1["id"], ORG, "annual", "assessor", "2020-01-01")
    overdue_org1 = engine.get_overdue_assessments(ORG)
    overdue_org2 = engine.get_overdue_assessments(ORG2)
    assert len(overdue_org1) == 1
    assert len(overdue_org2) == 0


def test_org_isolation_incidents(engine):
    v1 = _make_vendor(engine, org=ORG)
    v2 = _make_vendor(engine, org=ORG2)
    _make_incident(engine, v1["id"], org=ORG)
    s1 = engine.get_tprm_summary(ORG)
    s2 = engine.get_tprm_summary(ORG2)
    assert s1["open_incidents"] == 1
    assert s2["open_incidents"] == 0
