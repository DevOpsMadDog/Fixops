"""
Vendor Risk Engine Tests — ALDECI.

Tests for suite-core/core/vendor_risk_engine.py covering:
  1.  VendorRiskEngine instantiates with temp DB
  2.  assess_vendor returns VendorRiskAssessment
  3.  assess_vendor risk_score is 0-100
  4.  assess_vendor with SolarWinds name triggers breach match
  5.  assess_vendor with LastPass name triggers breach match
  6.  assess_vendor with Okta name triggers breach match
  7.  assess_vendor with CircleCI name triggers breach match
  8.  assess_vendor with no domain applies domain penalty
  9.  assess_vendor with non-resolvable domain applies DNS penalty
  10. assess_vendor secret data_access_level is high penalty
  11. assess_vendor fourth_party_vendors increases penalty
  12. check_vendor_cvss falls back to empty list on network error
  13. track_questionnaire returns a UUID string
  14. track_questionnaire with empty questions raises ValueError
  15. update_questionnaire changes status
  16. calculate_fourth_party_risk returns 0.0 for unknown vendor
  17. calculate_fourth_party_risk returns float 0-1
  18. generate_vendor_scorecard raises ValueError without prior assessment
  19. generate_vendor_scorecard returns VendorScorecard after assessment
  20. list_high_risk_vendors returns assessments below threshold
  21. get_assessment returns None for unknown vendor
  22. get_assessment returns dict after assess_vendor
  23. KNOWN_BREACHES includes solarwinds, okta, lastpass, circleci, log4j
  24. _score_to_risk_level boundaries
  25. _score_to_grade boundaries
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.vendor_risk_engine import (
    KNOWN_BREACHES,
    RiskLevel,
    VendorRiskEngine,
    VendorRiskAssessment,
    VendorScorecard,
    _score_to_grade,
    _score_to_risk_level,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path):
    return str(tmp_path / "test_engine.db")


@pytest.fixture
def engine(temp_db):
    return VendorRiskEngine(db_path=temp_db)


@pytest.fixture
def minimal_vendor():
    return {"name": "Acme Corp", "domain": None}


@pytest.fixture
def assessed_vendor(engine):
    """Vendor that has already been assessed — used by scorecard tests."""
    vendor = {
        "id": "test-vendor-1",
        "name": "SafeVendor Inc",
        "domain": None,
        "data_access_level": "internal",
        "fourth_party_vendors": [],
    }
    engine.assess_vendor(vendor)
    return vendor


# ---------------------------------------------------------------------------
# Test 1: Engine instantiates
# ---------------------------------------------------------------------------


def test_engine_instantiates(temp_db):
    eng = VendorRiskEngine(db_path=temp_db)
    assert eng is not None


# ---------------------------------------------------------------------------
# Test 2: assess_vendor returns VendorRiskAssessment
# ---------------------------------------------------------------------------


def test_assess_vendor_returns_assessment(engine, minimal_vendor):
    result = engine.assess_vendor(minimal_vendor)
    assert isinstance(result, VendorRiskAssessment)


# ---------------------------------------------------------------------------
# Test 3: risk_score is in 0-100 range
# ---------------------------------------------------------------------------


def test_assess_vendor_score_in_range(engine):
    vendor = {"name": "TestCo", "domain": None}
    result = engine.assess_vendor(vendor)
    assert 0.0 <= result.risk_score <= 100.0


# ---------------------------------------------------------------------------
# Test 4-7: Known breach database matches
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vendor_name,expected_key", [
    ("SolarWinds Orion", "solarwinds"),
    ("LastPass Password Manager", "lastpass"),
    ("Okta Identity Cloud", "okta"),
    ("CircleCI", "circleci"),
])
def test_assess_vendor_breach_match(engine, vendor_name, expected_key):
    result = engine.assess_vendor({"name": vendor_name})
    assert len(result.breach_matches) > 0, f"Expected breach match for '{vendor_name}'"
    keys = [b.get("vendor_key") for b in result.breach_matches]
    assert expected_key in keys


# ---------------------------------------------------------------------------
# Test 8: No domain applies domain penalty (score < 100)
# ---------------------------------------------------------------------------


def test_assess_vendor_no_domain_penalty(engine):
    vendor_no_domain = {"name": "NoDomainVendor", "domain": None}
    result = engine.assess_vendor(vendor_no_domain)
    # No domain → at minimum a 5-point domain penalty
    assert result.risk_score <= 95.0


# ---------------------------------------------------------------------------
# Test 9: Non-resolvable domain applies DNS penalty
# ---------------------------------------------------------------------------


def test_assess_vendor_bad_domain_penalty(engine):
    vendor = {"name": "BadDomainCo", "domain": "this-domain-definitely-does-not-exist-xyz.invalid"}
    result = engine.assess_vendor(vendor)
    # DNS failure → 15-point penalty minimum
    assert result.risk_score <= 85.0


# ---------------------------------------------------------------------------
# Test 10: Secret data access level has high penalty
# ---------------------------------------------------------------------------


def test_assess_vendor_secret_data_access_penalty(engine):
    vendor_secret = {"name": "SecretVendor", "domain": None, "data_access_level": "secret"}
    vendor_none = {"name": "NoneVendor", "domain": None, "data_access_level": "none"}
    result_secret = engine.assess_vendor(vendor_secret)
    result_none = engine.assess_vendor(vendor_none)
    # Secret should score at least 25 points lower than none
    assert result_secret.risk_score < result_none.risk_score


# ---------------------------------------------------------------------------
# Test 11: fourth_party_vendors increases penalty
# ---------------------------------------------------------------------------


def test_assess_vendor_fourth_party_penalty(engine):
    vendor_clean = {"name": "CleanVendor", "domain": None, "fourth_party_vendors": []}
    vendor_fp = {
        "name": "ChainedVendor",
        "domain": None,
        "fourth_party_vendors": ["fp1", "fp2", "fp3"],
    }
    r_clean = engine.assess_vendor(vendor_clean)
    r_fp = engine.assess_vendor(vendor_fp)
    # 3 fourth parties = 15-point additional penalty
    assert r_fp.risk_score < r_clean.risk_score


# ---------------------------------------------------------------------------
# Test 12: check_vendor_cvss falls back to empty list on error
# ---------------------------------------------------------------------------


def test_check_vendor_cvss_fallback(engine, monkeypatch):
    """Simulate network failure — should return empty list, not raise."""
    import urllib.request

    def _fail(*args, **kwargs):
        raise OSError("Network unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", _fail)
    result = engine.check_vendor_cvss("SomeVendor")
    assert isinstance(result, list)
    assert result == []


# ---------------------------------------------------------------------------
# Test 13: track_questionnaire returns a UUID string
# ---------------------------------------------------------------------------


def test_track_questionnaire_returns_id(engine):
    qid = engine.track_questionnaire(
        vendor_id="vendor-abc",
        questions={"q1": "Do you have MFA?", "q2": "Do you encrypt data at rest?"},
    )
    assert isinstance(qid, str)
    assert len(qid) == 36  # UUID4 format


# ---------------------------------------------------------------------------
# Test 14: track_questionnaire with empty questions raises ValueError
# ---------------------------------------------------------------------------


def test_track_questionnaire_empty_raises(engine):
    with pytest.raises(ValueError, match="at least one question"):
        engine.track_questionnaire(vendor_id="vendor-abc", questions={})


# ---------------------------------------------------------------------------
# Test 15: update_questionnaire changes status
# ---------------------------------------------------------------------------


def test_update_questionnaire_status(engine):
    qid = engine.track_questionnaire(
        vendor_id="vendor-xyz",
        questions={"q1": "Is SOC2 certified?"},
    )
    # No exception should be raised
    engine.update_questionnaire(qid, status="in_progress", completion_pct=50.0)
    engine.update_questionnaire(qid, status="completed", completion_pct=100.0)
    record = engine.get_questionnaire(qid)
    assert record["status"] == "completed"
    assert record["completion_pct"] == 100.0


# ---------------------------------------------------------------------------
# Test 16: calculate_fourth_party_risk returns 0.0 for unknown vendor
# ---------------------------------------------------------------------------


def test_fourth_party_risk_unknown_vendor(engine):
    score = engine.calculate_fourth_party_risk("nonexistent-vendor-id")
    assert score == 0.0


# ---------------------------------------------------------------------------
# Test 17: calculate_fourth_party_risk returns float 0-1
# ---------------------------------------------------------------------------


def test_fourth_party_risk_in_range(engine, assessed_vendor):
    score = engine.calculate_fourth_party_risk(assessed_vendor["id"])
    assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Test 18: generate_vendor_scorecard raises ValueError without assessment
# ---------------------------------------------------------------------------


def test_generate_scorecard_no_assessment_raises(engine):
    with pytest.raises(ValueError, match="No assessment found"):
        engine.generate_vendor_scorecard("never-assessed-vendor")


# ---------------------------------------------------------------------------
# Test 19: generate_vendor_scorecard returns VendorScorecard after assessment
# ---------------------------------------------------------------------------


def test_generate_scorecard_after_assessment(engine, assessed_vendor):
    scorecard = engine.generate_vendor_scorecard(assessed_vendor["id"])
    assert isinstance(scorecard, VendorScorecard)
    assert 0.0 <= scorecard.overall_score <= 100.0
    assert scorecard.grade in ("A", "B", "C", "D", "F")
    assert scorecard.risk_level in RiskLevel.__members__.values() or scorecard.risk_level.value in [
        r.value for r in RiskLevel
    ]


# ---------------------------------------------------------------------------
# Test 20: list_high_risk_vendors returns assessments below threshold
# ---------------------------------------------------------------------------


def test_list_high_risk_vendors(engine):
    # Assess a known-breach vendor to get a low score
    engine.assess_vendor({"name": "SolarWinds", "domain": None, "data_access_level": "secret"})
    high_risk = engine.list_high_risk_vendors(threshold=100.0)
    assert len(high_risk) >= 1


# ---------------------------------------------------------------------------
# Test 21: get_assessment returns None for unknown vendor
# ---------------------------------------------------------------------------


def test_get_assessment_unknown_vendor(engine):
    result = engine.get_assessment("this-vendor-does-not-exist")
    assert result is None


# ---------------------------------------------------------------------------
# Test 22: get_assessment returns dict after assess_vendor
# ---------------------------------------------------------------------------


def test_get_assessment_after_assess(engine):
    vendor = {"id": "vendor-check-22", "name": "CheckedVendor", "domain": None}
    engine.assess_vendor(vendor)
    result = engine.get_assessment("vendor-check-22")
    assert result is not None
    assert isinstance(result, dict)
    assert result["vendor_name"] == "CheckedVendor"


# ---------------------------------------------------------------------------
# Test 23: KNOWN_BREACHES includes required entries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["solarwinds", "okta", "lastpass", "circleci", "log4j"])
def test_known_breaches_contains_key(key):
    assert key in KNOWN_BREACHES
    breach = KNOWN_BREACHES[key]
    assert "severity" in breach
    assert "year" in breach
    assert "description" in breach


# ---------------------------------------------------------------------------
# Test 24: _score_to_risk_level boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score,expected_level", [
    (85.0, RiskLevel.LOW),
    (70.0, RiskLevel.MEDIUM),
    (50.0, RiskLevel.HIGH),
    (20.0, RiskLevel.CRITICAL),
    (80.0, RiskLevel.LOW),
    (60.0, RiskLevel.MEDIUM),
    (40.0, RiskLevel.HIGH),
    (39.9, RiskLevel.CRITICAL),
])
def test_score_to_risk_level(score, expected_level):
    assert _score_to_risk_level(score) == expected_level


# ---------------------------------------------------------------------------
# Test 25: _score_to_grade boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score,expected_grade", [
    (95.0, "A"),
    (85.0, "B"),
    (75.0, "C"),
    (65.0, "D"),
    (55.0, "F"),
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
    (59.9, "F"),
])
def test_score_to_grade(score, expected_grade):
    assert _score_to_grade(score) == expected_grade
