"""Tests for PrivacyImpactAssessmentEngine — 35+ tests."""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from core.privacy_impact_assessment_engine import PrivacyImpactAssessmentEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "pia_test.db")
    return PrivacyImpactAssessmentEngine(db_path=db)


ORG = "org-pia-1"
ORG2 = "org-pia-2"


# ---------------------------------------------------------------------------
# Assessment lifecycle
# ---------------------------------------------------------------------------

def test_create_assessment_basic(engine):
    a = engine.create_assessment(ORG, "Project Alpha")
    assert a["project_name"] == "Project Alpha"
    assert a["org_id"] == ORG
    assert a["status"] == "draft"
    assert a["risk_score"] == 0.0
    assert a["dpo_approved"] == 0
    assert a["assessment_type"] == "pia"


def test_create_assessment_all_fields(engine):
    a = engine.create_assessment(
        ORG,
        "Project Beta",
        assessment_type="dpia",
        data_controller="Corp A",
        data_processor="Vendor B",
        legal_basis="consent",
        data_categories=["health", "financial"],
        data_subjects=["employees", "customers"],
        retention_period_days=730,
        cross_border_transfer=True,
    )
    assert a["assessment_type"] == "dpia"
    assert a["legal_basis"] == "consent"
    assert a["cross_border_transfer"] == 1
    assert a["retention_period_days"] == 730
    cats = json.loads(a["data_categories"])
    assert "health" in cats


def test_create_assessment_cross_border_false(engine):
    a = engine.create_assessment(ORG, "NoCross", cross_border_transfer=False)
    assert a["cross_border_transfer"] == 0


def test_create_assessment_invalid_type(engine):
    with pytest.raises(ValueError, match="assessment_type"):
        engine.create_assessment(ORG, "Bad", assessment_type="invalid_type")


def test_create_assessment_invalid_legal_basis(engine):
    with pytest.raises(ValueError, match="legal_basis"):
        engine.create_assessment(ORG, "Bad", legal_basis="bribery")


def test_list_assessments_empty(engine):
    assert engine.list_assessments(ORG) == []


def test_list_assessments(engine):
    engine.create_assessment(ORG, "A1", assessment_type="pia")
    engine.create_assessment(ORG, "A2", assessment_type="dpia")
    results = engine.list_assessments(ORG)
    assert len(results) == 2


def test_list_assessments_filter_type(engine):
    engine.create_assessment(ORG, "A1", assessment_type="pia")
    engine.create_assessment(ORG, "A2", assessment_type="dpia")
    dpias = engine.list_assessments(ORG, assessment_type="dpia")
    assert len(dpias) == 1
    assert dpias[0]["assessment_type"] == "dpia"


def test_list_assessments_filter_status(engine):
    engine.create_assessment(ORG, "A1")
    results = engine.list_assessments(ORG, status="draft")
    assert len(results) == 1
    results_approved = engine.list_assessments(ORG, status="approved")
    assert len(results_approved) == 0


def test_get_assessment_not_found(engine):
    assert engine.get_assessment("nonexistent", ORG) is None


def test_get_assessment_returns_risks_and_consultations(engine):
    a = engine.create_assessment(ORG, "Full")
    engine.add_risk(a["id"], ORG, "data_breach")
    engine.add_consultation(a["id"], ORG, "DPO")
    result = engine.get_assessment(a["id"], ORG)
    assert len(result["risks"]) == 1
    assert len(result["consultations"]) == 1


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def test_add_risk_score_calculation(engine):
    a = engine.create_assessment(ORG, "Risk Test")
    # low=1, medium=2 → score=2
    r = engine.add_risk(a["id"], ORG, "data_breach", likelihood="low", impact="medium")
    assert r["risk_score"] == 2.0


def test_add_risk_score_high_critical(engine):
    a = engine.create_assessment(ORG, "High Risk")
    # high=3, critical=4 → score=12
    r = engine.add_risk(a["id"], ORG, "unauthorized_access", likelihood="high", impact="critical")
    assert r["risk_score"] == 12.0


def test_add_risk_critical_critical(engine):
    a = engine.create_assessment(ORG, "Max Risk")
    # critical=4 × critical=4 = 16
    r = engine.add_risk(a["id"], ORG, "data_breach", likelihood="critical", impact="critical")
    assert r["risk_score"] == 16.0


def test_add_risk_assessment_score_avg(engine):
    a = engine.create_assessment(ORG, "Avg Test")
    # risk1: low(1)*low(1)=1, risk2: high(3)*high(3)=9 → avg=5
    engine.add_risk(a["id"], ORG, "data_breach", likelihood="low", impact="low")
    engine.add_risk(a["id"], ORG, "unauthorized_access", likelihood="high", impact="high")
    updated = engine.get_assessment(a["id"], ORG)
    assert updated["risk_score"] == pytest.approx(5.0, abs=0.01)


def test_add_risk_level_critical(engine):
    a = engine.create_assessment(ORG, "Critical Level")
    # critical(4)*critical(4)=16 → avg=16 → critical (>=9)
    engine.add_risk(a["id"], ORG, "data_breach", likelihood="critical", impact="critical")
    updated = engine.get_assessment(a["id"], ORG)
    assert updated["risk_level"] == "critical"


def test_add_risk_level_high(engine):
    a = engine.create_assessment(ORG, "High Level")
    # high(3)*high(3)=9 → avg=9 → critical threshold is >=9, so critical
    engine.add_risk(a["id"], ORG, "data_breach", likelihood="high", impact="high")
    updated = engine.get_assessment(a["id"], ORG)
    assert updated["risk_level"] == "critical"


def test_add_risk_level_medium(engine):
    a = engine.create_assessment(ORG, "Medium Level")
    # medium(2)*medium(2)=4 → avg=4 → medium (>=3)
    engine.add_risk(a["id"], ORG, "data_breach", likelihood="medium", impact="medium")
    updated = engine.get_assessment(a["id"], ORG)
    assert updated["risk_level"] == "medium"


def test_add_risk_level_low(engine):
    a = engine.create_assessment(ORG, "Low Level")
    # low(1)*low(1)=1 → avg=1 → low (<3)
    engine.add_risk(a["id"], ORG, "data_breach", likelihood="low", impact="low")
    updated = engine.get_assessment(a["id"], ORG)
    assert updated["risk_level"] == "low"


def test_add_risk_invalid_category(engine):
    a = engine.create_assessment(ORG, "Inv Cat")
    with pytest.raises(ValueError, match="risk_category"):
        engine.add_risk(a["id"], ORG, "not_a_category")


def test_add_risk_invalid_likelihood(engine):
    a = engine.create_assessment(ORG, "Inv Like")
    with pytest.raises(ValueError, match="likelihood"):
        engine.add_risk(a["id"], ORG, "data_breach", likelihood="possible")


def test_add_risk_invalid_impact(engine):
    a = engine.create_assessment(ORG, "Inv Imp")
    with pytest.raises(ValueError, match="impact"):
        engine.add_risk(a["id"], ORG, "data_breach", impact="catastrophic")


def test_update_risk_status(engine):
    a = engine.create_assessment(ORG, "Status Test")
    r = engine.add_risk(a["id"], ORG, "data_breach")
    updated = engine.update_risk_status(r["id"], ORG, "mitigated")
    assert updated["status"] == "mitigated"


def test_update_risk_status_invalid(engine):
    a = engine.create_assessment(ORG, "Bad Status")
    r = engine.add_risk(a["id"], ORG, "data_breach")
    with pytest.raises(ValueError, match="status"):
        engine.update_risk_status(r["id"], ORG, "deleted")


def test_update_risk_status_not_found(engine):
    result = engine.update_risk_status("nonexistent", ORG, "mitigated")
    assert result is None


# ---------------------------------------------------------------------------
# Consultations
# ---------------------------------------------------------------------------

def test_add_consultation(engine):
    a = engine.create_assessment(ORG, "Consult Test")
    c = engine.add_consultation(a["id"], ORG, "DPO", required=True)
    assert c["consulted_party"] == "DPO"
    assert c["required"] == 1
    assert c["completed"] == 0


def test_complete_consultation(engine):
    a = engine.create_assessment(ORG, "Complete Consult")
    c = engine.add_consultation(a["id"], ORG, "Legal Team", required=False)
    completed = engine.complete_consultation(c["id"], ORG, "No objections")
    assert completed["completed"] == 1
    assert completed["outcome"] == "No objections"
    assert completed["completed_at"] is not None


def test_complete_consultation_not_found(engine):
    result = engine.complete_consultation("nonexistent", ORG, "outcome")
    assert result is None


# ---------------------------------------------------------------------------
# Approval workflow
# ---------------------------------------------------------------------------

def test_approve_assessment_success(engine):
    a = engine.create_assessment(ORG, "Approve Test")
    c = engine.add_consultation(a["id"], ORG, "DPO", required=True)
    engine.complete_consultation(c["id"], ORG, "Approved")
    result = engine.approve_assessment(a["id"], ORG, "dpo@corp.com")
    assert result["dpo_approved"] == 1
    assert result["status"] == "approved"
    assert result["approved_at"] is not None


def test_approve_assessment_fails_incomplete_required(engine):
    a = engine.create_assessment(ORG, "Fail Approve")
    engine.add_consultation(a["id"], ORG, "DPO", required=True)
    # Required consultation NOT completed
    with pytest.raises(ValueError, match="required consultation"):
        engine.approve_assessment(a["id"], ORG, "dpo@corp.com")


def test_approve_assessment_optional_not_blocking(engine):
    a = engine.create_assessment(ORG, "Optional Consult")
    engine.add_consultation(a["id"], ORG, "Legal", required=False)
    # Optional consultation not completed — should NOT block approval
    result = engine.approve_assessment(a["id"], ORG, "dpo@corp.com")
    assert result["dpo_approved"] == 1


# ---------------------------------------------------------------------------
# High-risk and summary
# ---------------------------------------------------------------------------

def test_get_high_risk_assessments(engine):
    a1 = engine.create_assessment(ORG, "Low Risk A")
    a2 = engine.create_assessment(ORG, "High Risk A")
    # Make a2 high risk: critical×critical=16 → critical level
    engine.add_risk(a2["id"], ORG, "data_breach", likelihood="critical", impact="critical")
    high_risk = engine.get_high_risk_assessments(ORG)
    ids = [h["id"] for h in high_risk]
    assert a2["id"] in ids
    assert a1["id"] not in ids


def test_get_summary_empty(engine):
    s = engine.get_summary(ORG)
    assert s["total"] == 0
    assert s["avg_risk_score"] == 0.0
    assert s["high_risk_count"] == 0
    assert s["pending_dpo_approval"] == 0


def test_get_summary_counts(engine):
    engine.create_assessment(ORG, "A1", assessment_type="pia")
    a2 = engine.create_assessment(ORG, "A2", assessment_type="dpia")
    engine.add_risk(a2["id"], ORG, "data_breach", likelihood="critical", impact="critical")
    s = engine.get_summary(ORG)
    assert s["total"] == 2
    assert s["by_type"].get("pia") == 1
    assert s["by_type"].get("dpia") == 1
    assert s["high_risk_count"] >= 1
    assert s["pending_dpo_approval"] >= 1


def test_get_summary_by_status(engine):
    a = engine.create_assessment(ORG, "A1")
    c = engine.add_consultation(a["id"], ORG, "DPO", required=False)
    engine.complete_consultation(c["id"], ORG, "OK")
    engine.approve_assessment(a["id"], ORG, "dpo@corp.com")
    engine.create_assessment(ORG, "A2")
    s = engine.get_summary(ORG)
    assert s["by_status"].get("draft", 0) == 1
    assert s["by_status"].get("approved", 0) == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_list(engine):
    engine.create_assessment(ORG, "Org1 A")
    engine.create_assessment(ORG2, "Org2 A")
    assert len(engine.list_assessments(ORG)) == 1
    assert len(engine.list_assessments(ORG2)) == 1


def test_org_isolation_get(engine):
    a = engine.create_assessment(ORG, "Secret")
    result = engine.get_assessment(a["id"], ORG2)
    assert result is None


def test_org_isolation_high_risk(engine):
    a = engine.create_assessment(ORG, "High")
    engine.add_risk(a["id"], ORG, "data_breach", likelihood="critical", impact="critical")
    assert len(engine.get_high_risk_assessments(ORG2)) == 0


def test_org_isolation_summary(engine):
    engine.create_assessment(ORG, "A")
    s = engine.get_summary(ORG2)
    assert s["total"] == 0
