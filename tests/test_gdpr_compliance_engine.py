"""Tests for GDPRComplianceEngine — processing activities and consent lifecycle."""

from __future__ import annotations

import pytest

from core.gdpr_compliance_engine import (
    GDPRComplianceEngine,
    ProcessingActivityCreate,
    ConsentCreate,
)


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_gdpr.db")
    return GDPRComplianceEngine(db_path=db)


ORG = "org-gdpr"
ORG2 = "org-other"


# ===========================================================================
# Processing Activity Tests
# ===========================================================================


def test_record_processing_activity_valid(engine):
    data = ProcessingActivityCreate(
        name="Marketing Analytics",
        purpose="Personalized advertising",
        lawful_basis="consent",
    )
    result = engine.record_processing_activity(ORG, data)
    assert result["id"]
    assert result["org_id"] == ORG
    assert result["name"] == "Marketing Analytics"
    assert result["purpose"] == "Personalized advertising"
    assert result["lawful_basis"] == "consent"
    assert result["status"] == "active"
    assert result["created_at"]
    assert isinstance(result["data_categories"], list)
    assert isinstance(result["recipients"], list)


def test_record_processing_activity_all_lawful_bases(engine):
    bases = [
        "consent", "contract", "legal_obligation",
        "vital_interests", "public_task", "legitimate_interests",
    ]
    for basis in bases:
        data = ProcessingActivityCreate(name=f"Activity {basis}", purpose="Test purpose", lawful_basis=basis)
        result = engine.record_processing_activity(ORG, data)
        assert result["lawful_basis"] == basis


def test_record_processing_activity_invalid_lawful_basis(engine):
    data = ProcessingActivityCreate(name="Bad Activity", purpose="Test", lawful_basis="unknown_basis")
    with pytest.raises(ValueError, match="lawful_basis"):
        engine.record_processing_activity(ORG, data)


def test_record_processing_activity_missing_name(engine):
    data = ProcessingActivityCreate(name="", purpose="Test", lawful_basis="consent")
    with pytest.raises(ValueError, match="name"):
        engine.record_processing_activity(ORG, data)


def test_record_processing_activity_missing_purpose(engine):
    data = ProcessingActivityCreate(name="Test", purpose="", lawful_basis="consent")
    with pytest.raises(ValueError, match="purpose"):
        engine.record_processing_activity(ORG, data)


def test_record_processing_activity_with_categories_and_recipients(engine):
    data = ProcessingActivityCreate(
        name="HR Processing",
        purpose="Employee management",
        lawful_basis="contract",
        data_categories=["pii", "financial"],
        recipients=["HR system", "Payroll vendor"],
        retention_period="7 years",
    )
    result = engine.record_processing_activity(ORG, data)
    assert result["data_categories"] == ["pii", "financial"]
    assert result["recipients"] == ["HR system", "Payroll vendor"]
    assert result["retention_period"] == "7 years"


def test_list_processing_activities_empty(engine):
    result = engine.list_processing_activities(ORG)
    assert result == []


def test_list_processing_activities_returns_all(engine):
    for i in range(3):
        engine.record_processing_activity(
            ORG, ProcessingActivityCreate(name=f"Activity {i}", purpose="Test", lawful_basis="consent")
        )
    result = engine.list_processing_activities(ORG)
    assert len(result) == 3


def test_list_processing_activities_filter_by_basis(engine):
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="A", purpose="p", lawful_basis="consent"))
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="B", purpose="p", lawful_basis="contract"))
    result = engine.list_processing_activities(ORG, lawful_basis="consent")
    assert len(result) == 1
    assert result[0]["lawful_basis"] == "consent"


def test_list_processing_activities_filter_by_status(engine):
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="Active", purpose="p", lawful_basis="consent"))
    result = engine.list_processing_activities(ORG, status="active")
    assert len(result) == 1
    assert result[0]["status"] == "active"

    result_inactive = engine.list_processing_activities(ORG, status="inactive")
    assert len(result_inactive) == 0


def test_activity_org_isolation(engine):
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="Org1 Activity", purpose="p", lawful_basis="consent"))
    result = engine.list_processing_activities(ORG2)
    assert result == []


# ===========================================================================
# Consent Tests
# ===========================================================================


def test_record_consent_valid(engine):
    data = ConsentCreate(subject_id="user-123", purpose="marketing")
    result = engine.record_consent(ORG, data)
    assert result["id"]
    assert result["org_id"] == ORG
    assert result["subject_id"] == "user-123"
    assert result["purpose"] == "marketing"
    assert result["consented"] is True
    assert result["recorded_at"]
    assert result["withdrawn_at"] is None


def test_record_consent_missing_subject_id(engine):
    data = ConsentCreate(subject_id="", purpose="marketing")
    with pytest.raises(ValueError, match="subject_id"):
        engine.record_consent(ORG, data)


def test_record_consent_missing_purpose(engine):
    data = ConsentCreate(subject_id="user-123", purpose="")
    with pytest.raises(ValueError, match="purpose"):
        engine.record_consent(ORG, data)


def test_record_consent_with_expiry(engine):
    data = ConsentCreate(subject_id="user-123", purpose="analytics", expires_at="2027-01-01T00:00:00Z")
    result = engine.record_consent(ORG, data)
    assert result["expires_at"] == "2027-01-01T00:00:00Z"


def test_list_consents_empty(engine):
    result = engine.list_consents(ORG)
    assert result == []


def test_list_consents_returns_all(engine):
    for i in range(3):
        engine.record_consent(ORG, ConsentCreate(subject_id=f"user-{i}", purpose="marketing"))
    result = engine.list_consents(ORG)
    assert len(result) == 3


def test_list_consents_filter_by_subject(engine):
    engine.record_consent(ORG, ConsentCreate(subject_id="user-A", purpose="marketing"))
    engine.record_consent(ORG, ConsentCreate(subject_id="user-B", purpose="analytics"))
    result = engine.list_consents(ORG, subject_id="user-A")
    assert len(result) == 1
    assert result[0]["subject_id"] == "user-A"


def test_withdraw_consent(engine):
    consent = engine.record_consent(ORG, ConsentCreate(subject_id="user-123", purpose="marketing"))
    withdrawn = engine.withdraw_consent(ORG, consent["id"], reason="User requested opt-out")
    assert withdrawn["consented"] is False
    assert withdrawn["withdrawn_at"] is not None
    assert withdrawn["withdraw_reason"] == "User requested opt-out"


def test_withdraw_consent_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.withdraw_consent(ORG, "nonexistent-id")


def test_withdraw_consent_default_reason(engine):
    consent = engine.record_consent(ORG, ConsentCreate(subject_id="user-123", purpose="marketing"))
    withdrawn = engine.withdraw_consent(ORG, consent["id"])
    assert withdrawn["consented"] is False
    # Empty string or None reason both acceptable
    assert withdrawn["withdraw_reason"] in ("", None)


def test_consent_org_isolation(engine):
    engine.record_consent(ORG, ConsentCreate(subject_id="user-123", purpose="marketing"))
    result = engine.list_consents(ORG2)
    assert result == []


# ===========================================================================
# GDPR Assessment Tests
# ===========================================================================


def test_gdpr_assessment_empty(engine):
    result = engine.run_gdpr_assessment(ORG)
    assert result["total_activities"] == 0
    assert result["active_activities"] == 0
    assert result["total_consents"] == 0
    assert result["active_consents"] == 0
    assert result["withdrawn_consents"] == 0
    assert result["consent_rate"] == 0.0
    assert result["compliance_score"] == 0.0
    assert result["activities_by_basis"] == {}


def test_gdpr_assessment_with_activities(engine):
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="A", purpose="p", lawful_basis="consent"))
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="B", purpose="p", lawful_basis="contract"))
    result = engine.run_gdpr_assessment(ORG)
    assert result["total_activities"] == 2
    assert result["active_activities"] == 2
    assert result["activities_by_basis"]["consent"] == 1
    assert result["activities_by_basis"]["contract"] == 1
    # Having active activities gives 50 pts base
    assert result["compliance_score"] >= 50.0


def test_gdpr_assessment_consent_rate_calculation(engine):
    engine.record_consent(ORG, ConsentCreate(subject_id="u1", purpose="marketing"))
    engine.record_consent(ORG, ConsentCreate(subject_id="u2", purpose="analytics"))
    c3 = engine.record_consent(ORG, ConsentCreate(subject_id="u3", purpose="marketing"))
    engine.withdraw_consent(ORG, c3["id"])

    result = engine.run_gdpr_assessment(ORG)
    assert result["total_consents"] == 3
    assert result["active_consents"] == 2
    assert result["withdrawn_consents"] == 1
    # 2/3 * 100 = 66.7%
    assert abs(result["consent_rate"] - 66.7) < 0.2


def test_gdpr_assessment_full_compliance_score(engine):
    """100% consent rate + active activities = compliance score 100."""
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="A", purpose="p", lawful_basis="consent"))
    engine.record_consent(ORG, ConsentCreate(subject_id="u1", purpose="marketing"))
    engine.record_consent(ORG, ConsentCreate(subject_id="u2", purpose="analytics"))

    result = engine.run_gdpr_assessment(ORG)
    # All consents active (100% rate) + active activities = 50+50 = 100
    assert result["compliance_score"] == 100.0


def test_gdpr_assessment_partial_compliance_score(engine):
    """Active activities but zero consents → score = 50."""
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="A", purpose="p", lawful_basis="contract"))
    result = engine.run_gdpr_assessment(ORG)
    assert result["compliance_score"] == 50.0


def test_gdpr_assessment_org_isolation(engine):
    engine.record_processing_activity(ORG, ProcessingActivityCreate(name="A", purpose="p", lawful_basis="consent"))
    engine.record_consent(ORG, ConsentCreate(subject_id="u1", purpose="marketing"))

    result_other = engine.run_gdpr_assessment(ORG2)
    assert result_other["total_activities"] == 0
    assert result_other["total_consents"] == 0
    assert result_other["compliance_score"] == 0.0


def test_gdpr_assessment_all_withdrawn_consent_rate_zero(engine):
    c1 = engine.record_consent(ORG, ConsentCreate(subject_id="u1", purpose="marketing"))
    engine.withdraw_consent(ORG, c1["id"])
    result = engine.run_gdpr_assessment(ORG)
    assert result["consent_rate"] == 0.0
    assert result["active_consents"] == 0
    assert result["withdrawn_consents"] == 1
