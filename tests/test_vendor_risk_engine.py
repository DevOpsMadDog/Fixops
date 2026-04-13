"""
Vendor Risk Engine Tests — ALDECI.

Tests for suite-core/core/vendor_risk_engine.py covering:
  1.  register_vendor returns dict with vendor_id
  2.  register_vendor with invalid tier raises ValueError
  3.  get_vendor returns registered vendor
  4.  list_vendors returns list
  5.  list_vendors tier filter works
  6.  start_assessment returns dict with questions list
  7.  questions list is non-empty (has template questions)
  8.  submit_response returns dict
  9.  complete_assessment returns dict with risk_score float
  10. risk_score between 0 and 100
  11. risk_level is one of low/medium/high/critical
  12. all-yes answers -> low risk (high score)
  13. all-no answers -> high risk (low score)
  14. by_domain dict has expected domain keys
  15. recommendations is list
  16. get_assessment_by_id returns completed assessment
  17. list_assessments_by_vendor returns list
  18. get_risk_register returns list
  19. get_questionnaire_template returns list of 10 questions
  20. Multiple vendors can be registered independently
  21. update_vendor changes name
  22. start_assessment raises ValueError for unknown vendor
  23. VendorRiskEngine instantiates with temp DB
  24. submit_response answer is stored correctly
  25. complete_assessment with mixed answers gives intermediate score
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.vendor_risk_engine import (
    QUESTIONNAIRE_TEMPLATE,
    RISK_DOMAINS,
    VENDOR_TIERS,
    VendorRiskEngine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh VendorRiskEngine per test."""
    return VendorRiskEngine(db_path=str(tmp_path / "test_vra.db"))


@pytest.fixture
def vendor(engine):
    """A registered vendor."""
    return engine.register_vendor(name="Acme Corp", tier="high", org_id="test-org")


@pytest.fixture
def assessment(engine, vendor):
    """An in-progress assessment."""
    return engine.start_assessment(vendor["vendor_id"])


@pytest.fixture
def completed_assessment(engine, vendor):
    """A fully completed assessment with all-yes answers."""
    a = engine.start_assessment(vendor["vendor_id"])
    for q in QUESTIONNAIRE_TEMPLATE:
        engine.submit_response(a["assessment_id"], q["id"], answer=True)
    return engine.complete_assessment(a["assessment_id"])


# ---------------------------------------------------------------------------
# Test 23: Engine instantiates with temp DB
# ---------------------------------------------------------------------------


def test_engine_instantiates(tmp_path):
    eng = VendorRiskEngine(db_path=str(tmp_path / "inst.db"))
    assert eng is not None


# ---------------------------------------------------------------------------
# Test 1: register_vendor returns dict with vendor_id
# ---------------------------------------------------------------------------


def test_register_vendor_returns_dict_with_vendor_id(engine):
    result = engine.register_vendor(name="TestCo", tier="medium")
    assert isinstance(result, dict)
    assert "vendor_id" in result
    assert result["vendor_id"].startswith("vendor-")


# ---------------------------------------------------------------------------
# Test 2: register_vendor with invalid tier raises ValueError
# ---------------------------------------------------------------------------


def test_register_vendor_invalid_tier_raises(engine):
    with pytest.raises(ValueError, match="Invalid tier"):
        engine.register_vendor(name="BadTier", tier="unknown_tier")


# ---------------------------------------------------------------------------
# Test 3: get_vendor returns registered vendor
# ---------------------------------------------------------------------------


def test_get_vendor_returns_registered(engine, vendor):
    fetched = engine.get_vendor(vendor["vendor_id"])
    assert fetched is not None
    assert fetched["vendor_id"] == vendor["vendor_id"]
    assert fetched["name"] == "Acme Corp"
    assert fetched["tier"] == "high"


# ---------------------------------------------------------------------------
# Test 4: list_vendors returns list
# ---------------------------------------------------------------------------


def test_list_vendors_returns_list(engine, vendor):
    result = engine.list_vendors(org_id="test-org")
    assert isinstance(result, list)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# Test 5: list_vendors tier filter works
# ---------------------------------------------------------------------------


def test_list_vendors_tier_filter(engine):
    engine.register_vendor(name="HighVendor", tier="high", org_id="filter-org")
    engine.register_vendor(name="LowVendor", tier="low", org_id="filter-org")
    high_only = engine.list_vendors(org_id="filter-org", tier="high")
    assert all(v["tier"] == "high" for v in high_only)
    low_only = engine.list_vendors(org_id="filter-org", tier="low")
    assert all(v["tier"] == "low" for v in low_only)


# ---------------------------------------------------------------------------
# Test 6: start_assessment returns dict with questions list
# ---------------------------------------------------------------------------


def test_start_assessment_returns_dict_with_questions(engine, vendor):
    a = engine.start_assessment(vendor["vendor_id"])
    assert isinstance(a, dict)
    assert "assessment_id" in a
    assert "questions" in a
    assert isinstance(a["questions"], list)


# ---------------------------------------------------------------------------
# Test 7: questions list is non-empty
# ---------------------------------------------------------------------------


def test_questions_list_is_non_empty(engine, vendor):
    a = engine.start_assessment(vendor["vendor_id"])
    assert len(a["questions"]) > 0


# ---------------------------------------------------------------------------
# Test 8: submit_response returns dict
# ---------------------------------------------------------------------------


def test_submit_response_returns_dict(engine, assessment):
    result = engine.submit_response(assessment["assessment_id"], "q1", answer=True)
    assert isinstance(result, dict)
    assert "assessment_id" in result
    assert "question_id" in result
    assert result["question_id"] == "q1"


# ---------------------------------------------------------------------------
# Test 9: complete_assessment returns dict with risk_score float
# ---------------------------------------------------------------------------


def test_complete_assessment_returns_dict_with_risk_score(engine, completed_assessment):
    assert isinstance(completed_assessment, dict)
    assert "risk_score" in completed_assessment
    assert isinstance(completed_assessment["risk_score"], float)


# ---------------------------------------------------------------------------
# Test 10: risk_score between 0 and 100
# ---------------------------------------------------------------------------


def test_risk_score_between_0_and_100(engine, completed_assessment):
    assert 0.0 <= completed_assessment["risk_score"] <= 100.0


# ---------------------------------------------------------------------------
# Test 11: risk_level is one of low/medium/high/critical
# ---------------------------------------------------------------------------


def test_risk_level_valid_value(engine, completed_assessment):
    assert completed_assessment["risk_level"] in ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Test 12: all-yes answers -> low risk (high score >= 80)
# ---------------------------------------------------------------------------


def test_all_yes_answers_low_risk(engine, completed_assessment):
    assert completed_assessment["risk_score"] >= 80.0
    assert completed_assessment["risk_level"] == "low"


# ---------------------------------------------------------------------------
# Test 13: all-no answers -> high risk (low score)
# ---------------------------------------------------------------------------


def test_all_no_answers_high_risk(engine, vendor):
    a = engine.start_assessment(vendor["vendor_id"])
    for q in QUESTIONNAIRE_TEMPLATE:
        engine.submit_response(a["assessment_id"], q["id"], answer=False)
    result = engine.complete_assessment(a["assessment_id"])
    assert result["risk_score"] == 0.0
    assert result["risk_level"] == "critical"


# ---------------------------------------------------------------------------
# Test 14: by_domain dict has expected domain keys
# ---------------------------------------------------------------------------


def test_by_domain_has_expected_keys(engine, completed_assessment):
    by_domain = completed_assessment["by_domain"]
    assert isinstance(by_domain, dict)
    for domain in RISK_DOMAINS:
        assert domain in by_domain, f"Missing domain: {domain}"


# ---------------------------------------------------------------------------
# Test 15: recommendations is list
# ---------------------------------------------------------------------------


def test_recommendations_is_list(engine, completed_assessment):
    assert isinstance(completed_assessment["recommendations"], list)


# ---------------------------------------------------------------------------
# Test 16: get_assessment_by_id returns completed assessment
# ---------------------------------------------------------------------------


def test_get_assessment_by_id_returns_completed(engine, completed_assessment):
    fetched = engine.get_assessment_by_id(completed_assessment["assessment_id"])
    assert fetched is not None
    assert fetched["assessment_id"] == completed_assessment["assessment_id"]
    assert fetched["state"] == "completed"


# ---------------------------------------------------------------------------
# Test 17: list_assessments_by_vendor returns list
# ---------------------------------------------------------------------------


def test_list_assessments_by_vendor_returns_list(engine, vendor, completed_assessment):
    result = engine.list_assessments_by_vendor(vendor_id=vendor["vendor_id"])
    assert isinstance(result, list)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# Test 18: get_risk_register returns list
# ---------------------------------------------------------------------------


def test_get_risk_register_returns_list(engine, vendor, completed_assessment):
    result = engine.get_risk_register(org_id="test-org")
    assert isinstance(result, list)
    assert len(result) >= 1
    # The vendor should have a latest risk score
    entry = next((v for v in result if v["vendor_id"] == vendor["vendor_id"]), None)
    assert entry is not None
    assert entry["latest_risk_score"] is not None


# ---------------------------------------------------------------------------
# Test 19: get_questionnaire_template returns list of 10 questions
# ---------------------------------------------------------------------------


def test_get_questionnaire_template_returns_10_questions(engine):
    template = engine.get_questionnaire_template()
    assert isinstance(template, list)
    assert len(template) == 10
    for q in template:
        assert "id" in q
        assert "domain" in q
        assert "question" in q
        assert "weight" in q


# ---------------------------------------------------------------------------
# Test 20: Multiple vendors can be registered independently
# ---------------------------------------------------------------------------


def test_multiple_vendors_registered_independently(engine):
    v1 = engine.register_vendor(name="VendorA", tier="critical", org_id="multi-org")
    v2 = engine.register_vendor(name="VendorB", tier="low", org_id="multi-org")
    assert v1["vendor_id"] != v2["vendor_id"]
    vendors = engine.list_vendors(org_id="multi-org")
    ids = [v["vendor_id"] for v in vendors]
    assert v1["vendor_id"] in ids
    assert v2["vendor_id"] in ids


# ---------------------------------------------------------------------------
# Test 21: update_vendor changes name
# ---------------------------------------------------------------------------


def test_update_vendor_changes_name(engine, vendor):
    updated = engine.update_vendor(vendor["vendor_id"], name="Updated Corp")
    assert updated["name"] == "Updated Corp"
    fetched = engine.get_vendor(vendor["vendor_id"])
    assert fetched["name"] == "Updated Corp"


# ---------------------------------------------------------------------------
# Test 22: start_assessment raises ValueError for unknown vendor
# ---------------------------------------------------------------------------


def test_start_assessment_unknown_vendor_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.start_assessment("vendor-does-not-exist")


# ---------------------------------------------------------------------------
# Test 24: submit_response answer is stored correctly
# ---------------------------------------------------------------------------


def test_submit_response_answer_stored_correctly(engine, assessment):
    engine.submit_response(assessment["assessment_id"], "q3", answer=True, notes="MFA enforced")
    result = engine.submit_response(assessment["assessment_id"], "q3", answer=False, notes="revoked")
    # Upsert: latest answer wins
    assert result["answer"] is False
    assert result["notes"] == "revoked"


# ---------------------------------------------------------------------------
# Test 25: complete_assessment with mixed answers gives intermediate score
# ---------------------------------------------------------------------------


def test_complete_assessment_mixed_answers_intermediate_score(engine, vendor):
    a = engine.start_assessment(vendor["vendor_id"])
    # Answer only the first 5 questions with True
    for q in QUESTIONNAIRE_TEMPLATE[:5]:
        engine.submit_response(a["assessment_id"], q["id"], answer=True)
    for q in QUESTIONNAIRE_TEMPLATE[5:]:
        engine.submit_response(a["assessment_id"], q["id"], answer=False)
    result = engine.complete_assessment(a["assessment_id"])
    # Score should be strictly between 0 and 100
    assert 0.0 < result["risk_score"] < 100.0
