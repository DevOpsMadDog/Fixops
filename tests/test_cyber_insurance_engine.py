"""Tests for CyberInsuranceEngine.

20 tests covering: init, policy CRUD, assessments, claim lifecycle,
stats, org isolation.
"""

from __future__ import annotations

import os
import pytest
from core.cyber_insurance_engine import CyberInsuranceEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "cyber_ins_test.db")
    return CyberInsuranceEngine(db_path=db)


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
# 2. Policy CRUD
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
# 3. Assessments
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
    # overall_score auto-computed
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
# 4. Claim lifecycle
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
# 5. Stats
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
# 6. Org isolation
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
