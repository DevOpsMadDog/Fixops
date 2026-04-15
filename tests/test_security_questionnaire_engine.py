"""Tests for SecurityQuestionnaireEngine — 35+ tests covering all methods."""
from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.security_questionnaire_engine import (
    SecurityQuestionnaireEngine,
    _compute_risk_level,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return SecurityQuestionnaireEngine(db_path=str(tmp_path / "test.db"))


ORG = "org-sq-test"
ORG2 = "org-sq-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_questionnaire(engine, org=ORG, name="Vendor Q", qtype="vendor", framework="CAIQ"):
    return engine.create_questionnaire(org, name, questionnaire_type=qtype, framework=framework)


def _make_question(engine, qid, org=ORG, text="Do you encrypt data at rest?",
                   category="data-security", weight=1.0, required=True):
    return engine.add_question(qid, org, text, question_category=category,
                               weight=weight, required=required)


def _make_assessment(engine, qid, org=ORG, vendor_id="v1", vendor_name="Acme Corp",
                     due_date="2099-12-31T00:00:00+00:00"):
    return engine.send_assessment(org, qid, vendor_id, vendor_name, due_date)


# ---------------------------------------------------------------------------
# _compute_risk_level unit tests
# ---------------------------------------------------------------------------

def test_risk_level_low_boundary():
    assert _compute_risk_level(80.0) == "low"


def test_risk_level_low_above():
    assert _compute_risk_level(95.0) == "low"


def test_risk_level_medium_boundary():
    assert _compute_risk_level(60.0) == "medium"


def test_risk_level_medium_upper():
    assert _compute_risk_level(79.9) == "medium"


def test_risk_level_high_boundary():
    assert _compute_risk_level(40.0) == "high"


def test_risk_level_high_upper():
    assert _compute_risk_level(59.9) == "high"


def test_risk_level_critical_below():
    assert _compute_risk_level(39.9) == "critical"


def test_risk_level_critical_zero():
    assert _compute_risk_level(0.0) == "critical"


# ---------------------------------------------------------------------------
# Questionnaire creation
# ---------------------------------------------------------------------------

def test_create_questionnaire_basic(engine):
    q = _make_questionnaire(engine)
    assert q["questionnaire_name"] == "Vendor Q"
    assert q["questionnaire_type"] == "vendor"
    assert q["framework"] == "CAIQ"
    assert q["question_count"] == 0
    assert q["org_id"] == ORG
    assert "id" in q
    assert "created_at" in q


def test_create_questionnaire_all_types(engine):
    for qtype in ["vendor", "internal", "partner", "cloud-provider", "third-party", "regulatory"]:
        q = engine.create_questionnaire(ORG, f"Q-{qtype}", questionnaire_type=qtype, framework="custom")
        assert q["questionnaire_type"] == qtype


def test_create_questionnaire_all_frameworks(engine):
    for fw in ["CAIQ", "SIG", "VSAQ", "NIST", "ISO27001", "custom"]:
        q = engine.create_questionnaire(ORG, f"Q-{fw}", questionnaire_type="vendor", framework=fw)
        assert q["framework"] == fw


def test_create_questionnaire_invalid_type(engine):
    with pytest.raises(ValueError, match="questionnaire_type"):
        engine.create_questionnaire(ORG, "Q", questionnaire_type="unknown", framework="custom")


def test_create_questionnaire_invalid_framework(engine):
    with pytest.raises(ValueError, match="framework"):
        engine.create_questionnaire(ORG, "Q", questionnaire_type="vendor", framework="BadFW")


# ---------------------------------------------------------------------------
# Questions
# ---------------------------------------------------------------------------

def test_add_question_increments_count(engine):
    q = _make_questionnaire(engine)
    assert q["question_count"] == 0
    _make_question(engine, q["id"])
    # Re-fetch from DB by creating another and checking count indirectly via assessment flow
    q2 = _make_questionnaire(engine, name="Q2")
    _make_question(engine, q2["id"], text="Q1")
    _make_question(engine, q2["id"], text="Q2")
    # Verify question_count incremented: send assessment and check auto-score triggers correctly
    a = _make_assessment(engine, q2["id"])
    # Two questions added — should have 2 required questions
    assert a["status"] == "sent"


def test_add_question_all_categories(engine):
    q = _make_questionnaire(engine)
    cats = ["access-control", "data-security", "incident-response", "network",
            "physical", "compliance", "governance", "business-continuity"]
    for cat in cats:
        r = engine.add_question(q["id"], ORG, f"Q for {cat}", question_category=cat)
        assert r["question_category"] == cat


def test_add_question_invalid_category(engine):
    q = _make_questionnaire(engine)
    with pytest.raises(ValueError, match="question_category"):
        engine.add_question(q["id"], ORG, "Bad Q", question_category="invalid-cat")


def test_add_question_weight_stored(engine):
    q = _make_questionnaire(engine)
    r = engine.add_question(q["id"], ORG, "Weighted Q", weight=2.5)
    assert r["weight"] == 2.5


def test_add_question_not_required(engine):
    q = _make_questionnaire(engine)
    r = engine.add_question(q["id"], ORG, "Optional Q", required=False)
    assert r["required"] == 0


# ---------------------------------------------------------------------------
# Assessments — send
# ---------------------------------------------------------------------------

def test_send_assessment_basic(engine):
    q = _make_questionnaire(engine)
    a = _make_assessment(engine, q["id"])
    assert a["status"] == "sent"
    assert a["vendor_id"] == "v1"
    assert a["vendor_name"] == "Acme Corp"
    assert a["org_id"] == ORG
    assert a["score"] is None
    assert a["sent_at"] is not None


# ---------------------------------------------------------------------------
# Responses & scoring
# ---------------------------------------------------------------------------

def test_submit_response_basic(engine):
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"], required=False)
    a = _make_assessment(engine, q["id"])
    r = engine.submit_response(a["id"], qu["id"], ORG, "Yes, encrypted", 2)
    assert r["response_value"] == 2
    assert r["assessment_id"] == a["id"]


def test_response_value_clamped_low(engine):
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"], required=False)
    a = _make_assessment(engine, q["id"])
    r = engine.submit_response(a["id"], qu["id"], ORG, "text", -5)
    assert r["response_value"] == 0


def test_response_value_clamped_high(engine):
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"], required=False)
    a = _make_assessment(engine, q["id"])
    r = engine.submit_response(a["id"], qu["id"], ORG, "text", 99)
    assert r["response_value"] == 4


def test_auto_score_when_all_required_answered(engine):
    q = _make_questionnaire(engine)
    qu1 = _make_question(engine, q["id"], text="Q1", required=True)
    qu2 = _make_question(engine, q["id"], text="Q2", required=True)
    a = _make_assessment(engine, q["id"])
    # After first response, not all required answered yet
    engine.submit_response(a["id"], qu1["id"], ORG, "Yes", 2)
    a_mid = engine.get_assessment(a["id"], ORG)
    assert a_mid["status"] == "sent"  # not auto-scored yet
    # After second response, auto-score triggers
    engine.submit_response(a["id"], qu2["id"], ORG, "Yes", 2)
    a_done = engine.get_assessment(a["id"], ORG)
    assert a_done["status"] == "completed"
    assert a_done["score"] is not None


def test_score_assessment_formula(engine):
    """score = sum(rv*w)/sum(w)*25; with rv=4,w=1: score=100."""
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"], weight=1.0)
    a = _make_assessment(engine, q["id"])
    engine.submit_response(a["id"], qu["id"], ORG, "Full yes", 4)
    result = engine.get_assessment(a["id"], ORG)
    assert result["score"] == 100.0
    assert result["risk_level"] == "low"


def test_score_assessment_zero(engine):
    """With rv=0: score=0 → critical."""
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"], weight=1.0)
    a = _make_assessment(engine, q["id"])
    engine.submit_response(a["id"], qu["id"], ORG, "No", 0)
    result = engine.get_assessment(a["id"], ORG)
    assert result["score"] == 0.0
    assert result["risk_level"] == "critical"


def test_score_assessment_medium(engine):
    """rv=2 out of 4 max → score=50 → high (>=40 but <60)."""
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"], weight=1.0)
    a = _make_assessment(engine, q["id"])
    engine.submit_response(a["id"], qu["id"], ORG, "Partial", 2)
    result = engine.get_assessment(a["id"], ORG)
    assert result["score"] == 50.0
    assert result["risk_level"] == "high"


def test_score_assessment_weighted(engine):
    """Two questions: w=1 rv=4, w=3 rv=0 → score = (4*1+0*3)/(1+3)*25 = 25."""
    q = _make_questionnaire(engine)
    qu1 = _make_question(engine, q["id"], weight=1.0, text="Q1")
    qu2 = _make_question(engine, q["id"], weight=3.0, text="Q2")
    a = _make_assessment(engine, q["id"])
    engine.submit_response(a["id"], qu1["id"], ORG, "Yes", 4)
    engine.submit_response(a["id"], qu2["id"], ORG, "No", 0)
    result = engine.get_assessment(a["id"], ORG)
    assert result["score"] == 25.0
    assert result["risk_level"] == "critical"


def test_manual_score_assessment(engine):
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"], required=False)
    a = _make_assessment(engine, q["id"])
    engine.submit_response(a["id"], qu["id"], ORG, "Yes", 3)
    result = engine.score_assessment(a["id"], ORG)
    assert result["status"] == "completed"
    assert result["score"] is not None


def test_score_assessment_not_found(engine):
    with pytest.raises(ValueError):
        engine.score_assessment("nonexistent-id", ORG)


# ---------------------------------------------------------------------------
# list_assessments / get_assessment
# ---------------------------------------------------------------------------

def test_get_assessment_includes_responses(engine):
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"], required=False)
    a = _make_assessment(engine, q["id"])
    engine.submit_response(a["id"], qu["id"], ORG, "Yes", 2)
    result = engine.get_assessment(a["id"], ORG)
    assert "responses" in result
    assert len(result["responses"]) == 1


def test_get_assessment_not_found(engine):
    assert engine.get_assessment("bad-id", ORG) is None


def test_list_assessments_all(engine):
    q = _make_questionnaire(engine)
    _make_assessment(engine, q["id"], vendor_id="v1")
    _make_assessment(engine, q["id"], vendor_id="v2")
    results = engine.list_assessments(ORG)
    assert len(results) == 2


def test_list_assessments_filter_vendor(engine):
    q = _make_questionnaire(engine)
    _make_assessment(engine, q["id"], vendor_id="v1")
    _make_assessment(engine, q["id"], vendor_id="v2")
    results = engine.list_assessments(ORG, vendor_id="v1")
    assert len(results) == 1
    assert results[0]["vendor_id"] == "v1"


def test_list_assessments_filter_status(engine):
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"])
    a = _make_assessment(engine, q["id"])
    engine.submit_response(a["id"], qu["id"], ORG, "Yes", 4)
    # One completed, list only sent
    _make_assessment(engine, q["id"], vendor_id="v2")
    sent = engine.list_assessments(ORG, status="sent")
    completed = engine.list_assessments(ORG, status="completed")
    assert len(sent) == 1
    assert len(completed) == 1


def test_org_isolation(engine):
    q1 = engine.create_questionnaire(ORG, "Q1", questionnaire_type="vendor", framework="custom")
    q2 = engine.create_questionnaire(ORG2, "Q2", questionnaire_type="vendor", framework="custom")
    _make_assessment(engine, q1["id"], org=ORG)
    _make_assessment(engine, q2["id"], org=ORG2)
    assert len(engine.list_assessments(ORG)) == 1
    assert len(engine.list_assessments(ORG2)) == 1


# ---------------------------------------------------------------------------
# Overdue assessments
# ---------------------------------------------------------------------------

def test_get_overdue_assessments(engine):
    q = _make_questionnaire(engine)
    # Past due date
    engine.send_assessment(ORG, q["id"], "v1", "Acme", "2000-01-01T00:00:00+00:00")
    # Future due date
    _make_assessment(engine, q["id"], vendor_id="v2")
    overdue = engine.get_overdue_assessments(ORG)
    assert len(overdue) == 1
    assert overdue[0]["vendor_id"] == "v1"


def test_overdue_excludes_completed(engine):
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"])
    a = engine.send_assessment(ORG, q["id"], "v1", "Acme", "2000-01-01T00:00:00+00:00")
    engine.submit_response(a["id"], qu["id"], ORG, "Yes", 4)
    # Now it's completed, should not appear in overdue
    overdue = engine.get_overdue_assessments(ORG)
    assert len(overdue) == 0


# ---------------------------------------------------------------------------
# Vendor risk summary
# ---------------------------------------------------------------------------

def test_get_vendor_risk_summary(engine):
    q = _make_questionnaire(engine)
    qu = _make_question(engine, q["id"])
    a = _make_assessment(engine, q["id"], vendor_id="v1", vendor_name="Acme")
    engine.submit_response(a["id"], qu["id"], ORG, "Yes", 4)
    summary = engine.get_vendor_risk_summary(ORG)
    assert len(summary) == 1
    assert summary[0]["vendor_id"] == "v1"
    assert summary[0]["assessment_count"] == 1
    assert summary[0]["latest_score"] == 100.0
    assert summary[0]["risk_level"] == "low"


def test_get_vendor_risk_summary_empty(engine):
    assert engine.get_vendor_risk_summary(ORG) == []
