"""Tests for CyberInsuranceEngine.

Covers both the original v1 API (backward-compat) and the new v2 extended API.
Total: 20 original + 30 v2 = 50 tests.
"""

from __future__ import annotations

import os
import pytest
from core.cyber_insurance_engine import CyberInsuranceEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "cyber_ins_test.db")
    return CyberInsuranceEngine(db_path=db)


# ===========================================================================
# ORIGINAL V1 TESTS (preserved exactly — backward compatibility)
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ci_init.db")
    CyberInsuranceEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ci_idem.db")
    CyberInsuranceEngine(db_path=db)
    CyberInsuranceEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. Policy CRUD (v1)
# ---------------------------------------------------------------------------

def test_add_policy_returns_dict(engine):
    pol = engine.add_policy("org1", {
        "carrier": "Chubb",
        "policy_number": "CH-2026-001",
        "coverage_type": "both",
        "coverage_limit": 5_000_000.0,
        "deductible": 100_000.0,
        "premium_annual": 50_000.0,
        "effective_date": "2026-01-01",
        "expiry_date": "2027-01-01",
        "status": "active",
        "covered_events": ["ransomware", "data_breach"],
    })
    assert pol["policy_id"]
    assert pol["carrier"] == "Chubb"
    assert pol["coverage_limit"] == 5_000_000.0
    assert pol["covered_events"] == ["ransomware", "data_breach"]
    assert pol["status"] == "active"


def test_add_policy_defaults(engine):
    pol = engine.add_policy("org1", {"carrier": "AIG"})
    assert pol["coverage_type"] == "both"
    assert pol["status"] == "active"
    assert pol["covered_events"] == []
    assert pol["coverage_limit"] == 0.0


def test_add_policy_invalid_coverage_type_defaults(engine):
    pol = engine.add_policy("org1", {"carrier": "X", "coverage_type": "bogus"})
    assert pol["coverage_type"] == "both"


def test_list_policies_empty(engine):
    assert engine.list_policies("org-none") == []


def test_list_policies_returns_all(engine):
    engine.add_policy("org2", {"carrier": "C1"})
    engine.add_policy("org2", {"carrier": "C2"})
    pols = engine.list_policies("org2")
    assert len(pols) == 2


def test_list_policies_covered_events_deserialized(engine):
    engine.add_policy("org3", {
        "carrier": "X",
        "covered_events": ["ransomware", "social_engineering"],
    })
    pols = engine.list_policies("org3")
    assert isinstance(pols[0]["covered_events"], list)
    assert "ransomware" in pols[0]["covered_events"]


# ---------------------------------------------------------------------------
# 3. Assessments (v1)
# ---------------------------------------------------------------------------

def test_create_assessment(engine):
    pol = engine.add_policy("org1", {"carrier": "AXA"})
    asmt = engine.create_assessment("org1", pol["policy_id"], {
        "mfa_score": 90,
        "backup_score": 80,
        "incident_response_score": 70,
        "patch_score": 85,
        "training_score": 75,
        "recommendations": ["Enable MFA on all admin accounts"],
    })
    assert asmt["assessment_id"]
    assert asmt["policy_id"] == pol["policy_id"]
    assert asmt["mfa_score"] == 90
    assert "Enable MFA" in asmt["recommendations"][0]
    assert asmt["overall_score"] == round((90 + 80 + 70 + 85 + 75) / 5)


def test_create_assessment_clamps_scores(engine):
    pol = engine.add_policy("org1", {"carrier": "X"})
    asmt = engine.create_assessment("org1", pol["policy_id"], {
        "mfa_score": 150,
        "backup_score": -10,
    })
    assert asmt["mfa_score"] == 100
    assert asmt["backup_score"] == 0


def test_list_assessments_empty(engine):
    assert engine.list_assessments("org-none") == []


def test_list_assessments_returns_all(engine):
    pol = engine.add_policy("org4", {"carrier": "Z"})
    engine.create_assessment("org4", pol["policy_id"], {})
    engine.create_assessment("org4", pol["policy_id"], {})
    asmts = engine.list_assessments("org4")
    assert len(asmts) == 2


# ---------------------------------------------------------------------------
# 4. Claim lifecycle (v1)
# ---------------------------------------------------------------------------

def test_file_claim_returns_dict(engine):
    pol = engine.add_policy("org1", {"carrier": "AIG"})
    claim = engine.file_claim("org1", {
        "policy_id": pol["policy_id"],
        "incident_type": "ransomware",
        "incident_date": "2026-03-15",
        "estimated_loss": 250_000.0,
        "adjuster": "John Smith",
    })
    assert claim["claim_id"]
    assert claim["status"] == "filed"
    assert claim["incident_type"] == "ransomware"
    assert claim["estimated_loss"] == 250_000.0
    assert claim["settlement_amount"] is None


def test_list_claims_empty(engine):
    assert engine.list_claims("org-none") == []


def test_list_claims_returns_all(engine):
    pol = engine.add_policy("org5", {"carrier": "X"})
    engine.file_claim("org5", {"policy_id": pol["policy_id"], "incident_type": "data_breach"})
    engine.file_claim("org5", {"policy_id": pol["policy_id"], "incident_type": "ransomware"})
    claims = engine.list_claims("org5")
    assert len(claims) == 2


def test_list_claims_filter_by_status(engine):
    pol = engine.add_policy("org6", {"carrier": "X"})
    c1 = engine.file_claim("org6", {"policy_id": pol["policy_id"]})
    c2 = engine.file_claim("org6", {"policy_id": pol["policy_id"]})
    engine.update_claim("org6", c2["claim_id"], "approved")

    filed = engine.list_claims("org6", status="filed")
    approved = engine.list_claims("org6", status="approved")
    assert len(filed) == 1
    assert len(approved) == 1


def test_update_claim_status(engine):
    pol = engine.add_policy("org1", {"carrier": "X"})
    claim = engine.file_claim("org1", {"policy_id": pol["policy_id"]})
    result = engine.update_claim("org1", claim["claim_id"], "under_review")
    assert result is True
    claims = engine.list_claims("org1", status="under_review")
    assert len(claims) == 1


def test_update_claim_with_settlement(engine):
    pol = engine.add_policy("org1", {"carrier": "X"})
    claim = engine.file_claim("org1", {"policy_id": pol["policy_id"], "estimated_loss": 100_000.0})
    engine.update_claim("org1", claim["claim_id"], "settled", settlement_amount=80_000.0)
    claims = engine.list_claims("org1", status="settled")
    assert claims[0]["settlement_amount"] == 80_000.0


def test_update_claim_invalid_status_returns_false(engine):
    pol = engine.add_policy("org1", {"carrier": "X"})
    claim = engine.file_claim("org1", {"policy_id": pol["policy_id"]})
    result = engine.update_claim("org1", claim["claim_id"], "INVALID_STATUS")
    assert result is False


# ---------------------------------------------------------------------------
# 5. Stats (v1)
# ---------------------------------------------------------------------------

def test_get_insurance_stats_empty(engine):
    stats = engine.get_insurance_stats("org-empty")
    assert stats["total_coverage"] == 0
    assert stats["active_policies"] == 0
    assert stats["open_claims"] == 0
    assert stats["total_settled"] == 0
    assert stats["avg_premium"] == 0
    assert stats["coverage_gap_analysis"]["gap"] == 0


def test_get_insurance_stats_populated(engine):
    pol = engine.add_policy("org7", {
        "carrier": "AIG",
        "coverage_limit": 1_000_000.0,
        "premium_annual": 20_000.0,
        "status": "active",
    })
    pol2 = engine.add_policy("org7", {
        "carrier": "Chubb",
        "coverage_limit": 500_000.0,
        "premium_annual": 10_000.0,
        "status": "active",
    })
    c1 = engine.file_claim("org7", {"policy_id": pol["policy_id"], "estimated_loss": 200_000.0})
    engine.update_claim("org7", c1["claim_id"], "settled", settlement_amount=150_000.0)
    engine.file_claim("org7", {"policy_id": pol2["policy_id"], "estimated_loss": 50_000.0})

    stats = engine.get_insurance_stats("org7")
    assert stats["active_policies"] == 2
    assert stats["total_coverage"] == 1_500_000.0
    assert stats["total_settled"] == 150_000.0
    assert stats["open_claims"] == 1
    assert stats["avg_premium"] == 15_000.0


# ---------------------------------------------------------------------------
# 6. Org isolation (v1)
# ---------------------------------------------------------------------------

def test_org_isolation_policies(engine):
    engine.add_policy("org-a", {"carrier": "A"})
    engine.add_policy("org-b", {"carrier": "B"})
    assert len(engine.list_policies("org-a")) == 1
    assert len(engine.list_policies("org-b")) == 1


def test_org_isolation_claims(engine):
    pol_a = engine.add_policy("org-c", {"carrier": "A"})
    pol_b = engine.add_policy("org-d", {"carrier": "B"})
    engine.file_claim("org-c", {"policy_id": pol_a["policy_id"]})
    engine.file_claim("org-d", {"policy_id": pol_b["policy_id"]})
    assert len(engine.list_claims("org-c")) == 1
    assert len(engine.list_claims("org-d")) == 1


# ===========================================================================
# V2 EXTENDED TESTS
# ===========================================================================

# ---------------------------------------------------------------------------
# 7. policies_v2 — tier assignment
# ---------------------------------------------------------------------------

def test_add_policy_v2_returns_dict(engine):
    pol = engine.add_policy_v2("org1", {
        "policy_name": "Enterprise Cyber Shield",
        "insurer": "AIG",
        "policy_number": "AIG-2026-001",
        "policy_type": "combined",
        "coverage_limit_usd": 10_000_000.0,
        "deductible_usd": 250_000.0,
        "premium_annual_usd": 120_000.0,
        "coverage_types": ["ransomware", "data_breach", "business_interruption"],
        "effective_date": "2026-01-01",
        "expiry_date": "2027-01-01",
        "status": "active",
    })
    assert pol["id"]
    assert pol["policy_name"] == "Enterprise Cyber Shield"
    assert pol["tier"] == "gold"  # 10M >= 5M but < 20M
    assert isinstance(pol["coverage_types"], list)


def test_add_policy_v2_tier_bronze(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "Basic", "coverage_limit_usd": 500_000.0})
    assert pol["tier"] == "bronze"


def test_add_policy_v2_tier_silver(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "Mid", "coverage_limit_usd": 2_000_000.0})
    assert pol["tier"] == "silver"


def test_add_policy_v2_tier_platinum(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "Mega", "coverage_limit_usd": 50_000_000.0})
    assert pol["tier"] == "platinum"


def test_add_policy_v2_missing_name_raises(engine):
    with pytest.raises(ValueError, match="policy_name"):
        engine.add_policy_v2("org1", {"coverage_limit_usd": 1_000_000.0})


def test_add_policy_v2_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.add_policy_v2("org1", {"policy_name": "X", "policy_type": "bogus"})


def test_list_policies_v2_empty(engine):
    assert engine.list_policies_v2("org-none") == []


def test_list_policies_v2_filter_by_status(engine):
    engine.add_policy_v2("org8", {"policy_name": "A", "status": "active"})
    engine.add_policy_v2("org8", {"policy_name": "B", "status": "pending"})
    active = engine.list_policies_v2("org8", status="active")
    assert len(active) == 1
    assert active[0]["status"] == "active"


def test_get_policy_v2_includes_claims_summary(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "Shield"})
    engine.file_claim_v2("org1", {
        "policy_id": pol["id"],
        "incident_type": "ransomware",
        "claim_amount_usd": 300_000.0,
    })
    result = engine.get_policy_v2("org1", pol["id"])
    assert result is not None
    assert result["claims_count"] == 1
    assert result["total_claimed_usd"] == 300_000.0


def test_get_policy_v2_missing_returns_none(engine):
    assert engine.get_policy_v2("org1", "no-such-id") is None


# ---------------------------------------------------------------------------
# 8. claims_v2 lifecycle
# ---------------------------------------------------------------------------

def test_file_claim_v2_returns_dict(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "P"})
    claim = engine.file_claim_v2("org1", {
        "policy_id": pol["id"],
        "incident_type": "data_breach",
        "claim_amount_usd": 500_000.0,
        "adjuster_name": "Jane Doe",
        "incident_description": "PII exposed via misconfigured S3 bucket",
    })
    assert claim["id"]
    assert claim["status"] == "submitted"
    assert claim["claim_amount_usd"] == 500_000.0
    assert claim["settled_amount_usd"] == 0.0


def test_file_claim_v2_missing_policy_id_raises(engine):
    with pytest.raises(ValueError, match="policy_id"):
        engine.file_claim_v2("org1", {"incident_type": "fraud"})


def test_file_claim_v2_invalid_incident_type_raises(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "P"})
    with pytest.raises(ValueError):
        engine.file_claim_v2("org1", {"policy_id": pol["id"], "incident_type": "earthquake"})


def test_update_claim_v2_status(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "P"})
    claim = engine.file_claim_v2("org1", {"policy_id": pol["id"], "incident_type": "ddos"})
    ok = engine.update_claim_v2("org1", claim["id"], "under_review")
    assert ok is True
    claims = engine.list_claims_v2("org1", status="under_review")
    assert len(claims) == 1


def test_update_claim_v2_settled_with_amount(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "P"})
    claim = engine.file_claim_v2("org1", {"policy_id": pol["id"], "incident_type": "fraud",
                                           "claim_amount_usd": 200_000.0})
    engine.update_claim_v2("org1", claim["id"], "settled", settled_amount=175_000.0)
    settled = engine.list_claims_v2("org1", status="settled")
    assert settled[0]["settled_amount_usd"] == 175_000.0


def test_update_claim_v2_invalid_status_raises(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "P"})
    claim = engine.file_claim_v2("org1", {"policy_id": pol["id"], "incident_type": "ddos"})
    with pytest.raises(ValueError):
        engine.update_claim_v2("org1", claim["id"], "BOGUS")


def test_list_claims_v2_filter_by_policy(engine):
    pol1 = engine.add_policy_v2("org9", {"policy_name": "P1"})
    pol2 = engine.add_policy_v2("org9", {"policy_name": "P2"})
    engine.file_claim_v2("org9", {"policy_id": pol1["id"], "incident_type": "ransomware"})
    engine.file_claim_v2("org9", {"policy_id": pol2["id"], "incident_type": "fraud"})
    pol1_claims = engine.list_claims_v2("org9", policy_id=pol1["id"])
    assert len(pol1_claims) == 1


# ---------------------------------------------------------------------------
# 9. Coverage gaps
# ---------------------------------------------------------------------------

def test_add_coverage_gap(engine):
    gap = engine.add_coverage_gap("org1", {
        "gap_type": "uncovered_attack_vector",
        "severity": "critical",
        "description": "No coverage for state-sponsored APT attacks",
        "estimated_exposure_usd": 5_000_000.0,
        "recommendation": "Negotiate APT rider with insurer",
    })
    assert gap["id"]
    assert gap["gap_type"] == "uncovered_attack_vector"
    assert gap["severity"] == "critical"


def test_add_coverage_gap_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.add_coverage_gap("org1", {"gap_type": "wrong_type", "severity": "high"})


def test_add_coverage_gap_invalid_severity_raises(engine):
    with pytest.raises(ValueError):
        engine.add_coverage_gap("org1", {"gap_type": "exclusion", "severity": "catastrophic"})


def test_list_coverage_gaps_sorted_by_severity(engine):
    engine.add_coverage_gap("org1", {"gap_type": "exclusion", "severity": "low"})
    engine.add_coverage_gap("org1", {"gap_type": "sublimit", "severity": "critical"})
    engine.add_coverage_gap("org1", {"gap_type": "low_limit", "severity": "high"})
    gaps = engine.list_coverage_gaps("org1")
    severities = [g["severity"] for g in gaps]
    assert severities[0] == "critical"
    assert severities[-1] == "low"


def test_list_coverage_gaps_filter_severity(engine):
    engine.add_coverage_gap("org1", {"gap_type": "exclusion", "severity": "high"})
    engine.add_coverage_gap("org1", {"gap_type": "sublimit", "severity": "medium"})
    high = engine.list_coverage_gaps("org1", severity="high")
    assert len(high) == 1
    assert high[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# 10. Risk assessments
# ---------------------------------------------------------------------------

def test_create_risk_assessment(engine):
    pol = engine.add_policy_v2("org1", {"policy_name": "P"})
    ra = engine.create_risk_assessment("org1", pol["id"], {
        "assessment_type": "renewal",
        "overall_risk_score": 72.5,
        "security_posture_score": 80.0,
        "incident_history_score": 65.0,
        "control_effectiveness": 75.0,
        "recommendations": ["Implement ZTNA", "Improve backup frequency"],
    })
    assert ra["id"]
    assert ra["assessment_type"] == "renewal"
    assert ra["overall_risk_score"] == 72.5
    assert isinstance(ra["recommendations"], list)
    assert len(ra["recommendations"]) == 2


def test_create_risk_assessment_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.create_risk_assessment("org1", "pol-id", {"assessment_type": "annual"})


# ---------------------------------------------------------------------------
# 11. V2 stats
# ---------------------------------------------------------------------------

def test_get_insurance_stats_v2_empty(engine):
    stats = engine.get_insurance_stats_v2("org-empty-v2")
    assert stats["active_policies"] == 0
    assert stats["total_coverage_limit"] == 0.0
    assert stats["total_premium"] == 0.0
    assert stats["open_claims"] == 0
    assert stats["total_claimed"] == 0.0
    assert stats["settlement_rate"] == 0.0
    assert stats["coverage_gaps"] == 0
    assert stats["expiring_soon"] == 0
    assert stats["avg_risk_score"] == 0.0


def test_get_insurance_stats_v2_settlement_rate(engine):
    pol = engine.add_policy_v2("org10", {"policy_name": "P", "status": "active"})
    c1 = engine.file_claim_v2("org10", {"policy_id": pol["id"], "incident_type": "ransomware"})
    c2 = engine.file_claim_v2("org10", {"policy_id": pol["id"], "incident_type": "fraud"})
    engine.update_claim_v2("org10", c1["id"], "settled", settled_amount=50_000.0)
    stats = engine.get_insurance_stats_v2("org10")
    assert stats["settlement_rate"] == 0.5  # 1 of 2 settled


def test_get_insurance_stats_v2_expiring_soon(engine):
    # Policy expiring in 30 days (within 90-day window)
    from datetime import datetime, timezone, timedelta
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    engine.add_policy_v2("org11", {
        "policy_name": "Expiring",
        "status": "active",
        "expiry_date": soon,
    })
    stats = engine.get_insurance_stats_v2("org11")
    assert stats["expiring_soon"] == 1


def test_get_insurance_stats_v2_avg_risk_score(engine):
    pol = engine.add_policy_v2("org12", {"policy_name": "P"})
    engine.create_risk_assessment("org12", pol["id"], {"overall_risk_score": 60.0})
    engine.create_risk_assessment("org12", pol["id"], {"overall_risk_score": 80.0})
    stats = engine.get_insurance_stats_v2("org12")
    assert stats["avg_risk_score"] == 70.0


# ---------------------------------------------------------------------------
# 12. V2 org isolation
# ---------------------------------------------------------------------------

def test_v2_org_isolation_policies(engine):
    engine.add_policy_v2("org-aa", {"policy_name": "PA"})
    engine.add_policy_v2("org-bb", {"policy_name": "PB"})
    assert len(engine.list_policies_v2("org-aa")) == 1
    assert len(engine.list_policies_v2("org-bb")) == 1


def test_v2_org_isolation_coverage_gaps(engine):
    engine.add_coverage_gap("org-cc", {"gap_type": "exclusion", "severity": "high"})
    engine.add_coverage_gap("org-dd", {"gap_type": "sublimit", "severity": "low"})
    assert len(engine.list_coverage_gaps("org-cc")) == 1
    assert len(engine.list_coverage_gaps("org-dd")) == 1
