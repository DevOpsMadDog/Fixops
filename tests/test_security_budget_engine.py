"""Tests for SecurityBudgetEngine — ALDECI.

Covers:
- Budget allocation CRUD
- All valid categories
- Invalid category validation
- Spend transaction recording (spent_amount increment)
- Approve spend workflow
- ROI assessment with calculated_roi formula
- get_budget_stats aggregations
- Org isolation
- ~35 tests
"""
from __future__ import annotations

import sys
import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.security_budget_engine import SecurityBudgetEngine, _VALID_CATEGORIES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return SecurityBudgetEngine(db_path=str(tmp_path / "budget.db"))


def _alloc(engine, org_id="org1", fiscal_year=2026, category="tools", amount=10000.0):
    return engine.create_allocation(org_id, {
        "fiscal_year": fiscal_year,
        "category": category,
        "allocated_amount": amount,
    })


# ---------------------------------------------------------------------------
# create_allocation
# ---------------------------------------------------------------------------


def test_create_allocation_basic(engine):
    a = _alloc(engine)
    assert a["id"]
    assert a["org_id"] == "org1"
    assert a["fiscal_year"] == 2026
    assert a["category"] == "tools"
    assert a["allocated_amount"] == 10000.0
    assert a["spent_amount"] == 0.0
    assert a["currency"] == "USD"


def test_create_allocation_all_valid_categories(engine):
    for i, cat in enumerate(sorted(_VALID_CATEGORIES)):
        a = engine.create_allocation("org1", {
            "fiscal_year": 2026,
            "category": cat,
            "allocated_amount": float(1000 + i),
        })
        assert a["category"] == cat


def test_create_allocation_invalid_category(engine):
    with pytest.raises(ValueError, match="category"):
        engine.create_allocation("org1", {
            "fiscal_year": 2026,
            "category": "invalid_cat",
            "allocated_amount": 5000.0,
        })


def test_create_allocation_invalid_fiscal_year_zero(engine):
    with pytest.raises(ValueError, match="fiscal_year"):
        engine.create_allocation("org1", {
            "fiscal_year": 0,
            "category": "tools",
            "allocated_amount": 5000.0,
        })


def test_create_allocation_invalid_fiscal_year_negative(engine):
    with pytest.raises(ValueError, match="fiscal_year"):
        engine.create_allocation("org1", {
            "fiscal_year": -1,
            "category": "tools",
            "allocated_amount": 5000.0,
        })


def test_create_allocation_invalid_amount_zero(engine):
    with pytest.raises(ValueError, match="allocated_amount"):
        engine.create_allocation("org1", {
            "fiscal_year": 2026,
            "category": "tools",
            "allocated_amount": 0.0,
        })


def test_create_allocation_invalid_amount_negative(engine):
    with pytest.raises(ValueError, match="allocated_amount"):
        engine.create_allocation("org1", {
            "fiscal_year": 2026,
            "category": "tools",
            "allocated_amount": -100.0,
        })


def test_create_allocation_with_notes_and_currency(engine):
    a = engine.create_allocation("org1", {
        "fiscal_year": 2025,
        "category": "personnel",
        "allocated_amount": 50000.0,
        "currency": "EUR",
        "notes": "Security team salaries",
    })
    assert a["currency"] == "EUR"
    assert a["notes"] == "Security team salaries"


# ---------------------------------------------------------------------------
# list_allocations / get_allocation
# ---------------------------------------------------------------------------


def test_list_allocations_empty(engine):
    assert engine.list_allocations("org1") == []


def test_list_allocations_returns_all(engine):
    _alloc(engine, category="tools")
    _alloc(engine, category="personnel")
    result = engine.list_allocations("org1")
    assert len(result) == 2


def test_list_allocations_filter_fiscal_year(engine):
    _alloc(engine, fiscal_year=2025, category="tools")
    _alloc(engine, fiscal_year=2026, category="tools")
    result = engine.list_allocations("org1", fiscal_year=2025)
    assert len(result) == 1
    assert result[0]["fiscal_year"] == 2025


def test_list_allocations_filter_category(engine):
    _alloc(engine, category="tools")
    _alloc(engine, category="training")
    result = engine.list_allocations("org1", category="training")
    assert len(result) == 1
    assert result[0]["category"] == "training"


def test_get_allocation_found(engine):
    a = _alloc(engine)
    found = engine.get_allocation("org1", a["id"])
    assert found["id"] == a["id"]


def test_get_allocation_not_found(engine):
    assert engine.get_allocation("org1", "nonexistent") is None


def test_get_allocation_wrong_org(engine):
    a = _alloc(engine, org_id="org1")
    assert engine.get_allocation("org2", a["id"]) is None


# ---------------------------------------------------------------------------
# record_spend / approve_spend
# ---------------------------------------------------------------------------


def test_record_spend_basic(engine):
    a = _alloc(engine, amount=10000.0)
    tx = engine.record_spend("org1", a["id"], {
        "vendor_name": "CrowdStrike",
        "amount": 2500.0,
    })
    assert tx["id"]
    assert tx["vendor_name"] == "CrowdStrike"
    assert tx["amount"] == 2500.0
    assert tx["approval_status"] == "pending"


def test_record_spend_increments_spent_amount(engine):
    a = _alloc(engine, amount=10000.0)
    engine.record_spend("org1", a["id"], {"vendor_name": "VendorA", "amount": 3000.0})
    engine.record_spend("org1", a["id"], {"vendor_name": "VendorB", "amount": 1500.0})
    updated = engine.get_allocation("org1", a["id"])
    assert updated["spent_amount"] == pytest.approx(4500.0)


def test_record_spend_invalid_amount_zero(engine):
    a = _alloc(engine)
    with pytest.raises(ValueError, match="amount"):
        engine.record_spend("org1", a["id"], {"vendor_name": "V", "amount": 0.0})


def test_record_spend_missing_vendor_name(engine):
    a = _alloc(engine)
    with pytest.raises(ValueError, match="vendor_name"):
        engine.record_spend("org1", a["id"], {"vendor_name": "", "amount": 100.0})


def test_record_spend_wrong_org_allocation(engine):
    a = _alloc(engine, org_id="org1")
    with pytest.raises(ValueError):
        engine.record_spend("org2", a["id"], {"vendor_name": "V", "amount": 100.0})


def test_approve_spend(engine):
    a = _alloc(engine)
    tx = engine.record_spend("org1", a["id"], {"vendor_name": "V", "amount": 500.0})
    approved = engine.approve_spend("org1", tx["id"], "alice")
    assert approved["approval_status"] == "approved"
    assert approved["approved_by"] == "alice"


def test_approve_spend_wrong_org(engine):
    a = _alloc(engine, org_id="org1")
    tx = engine.record_spend("org1", a["id"], {"vendor_name": "V", "amount": 100.0})
    with pytest.raises(ValueError):
        engine.approve_spend("org2", tx["id"], "bob")


def test_list_transactions_filter_approval_status(engine):
    a = _alloc(engine)
    tx1 = engine.record_spend("org1", a["id"], {"vendor_name": "V1", "amount": 100.0})
    tx2 = engine.record_spend("org1", a["id"], {"vendor_name": "V2", "amount": 200.0})
    engine.approve_spend("org1", tx1["id"], "admin")
    pending = engine.list_transactions("org1", approval_status="pending")
    approved = engine.list_transactions("org1", approval_status="approved")
    assert len(pending) == 1
    assert len(approved) == 1


# ---------------------------------------------------------------------------
# ROI assessments
# ---------------------------------------------------------------------------


def test_record_roi_assessment_formula(engine):
    roi = engine.record_roi_assessment("org1", {
        "initiative_name": "MFA rollout",
        "investment_amount": 20000.0,
        "estimated_risk_reduction": 40.0,
    })
    # formula: min(500, max(0, 40 * 50)) = min(500, 2000) = 500? No: 40*50=2000 > 500 → 500
    # Wait: 40 * 50 = 2000, clamped to 500
    assert roi["calculated_roi"] == pytest.approx(500.0)


def test_record_roi_assessment_low_reduction(engine):
    roi = engine.record_roi_assessment("org1", {
        "initiative_name": "Pen test",
        "investment_amount": 5000.0,
        "estimated_risk_reduction": 8.0,
    })
    # 8 * 50 = 400, within 0-500
    assert roi["calculated_roi"] == pytest.approx(400.0)


def test_record_roi_assessment_zero_reduction(engine):
    roi = engine.record_roi_assessment("org1", {
        "initiative_name": "Audit prep",
        "investment_amount": 1000.0,
        "estimated_risk_reduction": 0.0,
    })
    assert roi["calculated_roi"] == pytest.approx(0.0)


def test_record_roi_assessment_missing_initiative(engine):
    with pytest.raises(ValueError, match="initiative_name"):
        engine.record_roi_assessment("org1", {
            "initiative_name": "",
            "investment_amount": 1000.0,
            "estimated_risk_reduction": 10.0,
        })


def test_record_roi_assessment_invalid_risk_reduction(engine):
    with pytest.raises(ValueError, match="estimated_risk_reduction"):
        engine.record_roi_assessment("org1", {
            "initiative_name": "X",
            "investment_amount": 1000.0,
            "estimated_risk_reduction": 150.0,
        })


def test_list_roi_assessments(engine):
    engine.record_roi_assessment("org1", {
        "initiative_name": "A", "investment_amount": 1000.0, "estimated_risk_reduction": 5.0
    })
    engine.record_roi_assessment("org1", {
        "initiative_name": "B", "investment_amount": 2000.0, "estimated_risk_reduction": 10.0
    })
    result = engine.list_roi_assessments("org1")
    assert len(result) == 2


# ---------------------------------------------------------------------------
# get_budget_stats
# ---------------------------------------------------------------------------


def test_get_budget_stats_empty(engine):
    stats = engine.get_budget_stats("org1")
    assert stats["total_allocated"] == 0.0
    assert stats["total_spent"] == 0.0
    assert stats["utilization_pct"] == 0.0
    assert stats["pending_transactions"] == 0


def test_get_budget_stats_totals(engine):
    a1 = _alloc(engine, category="tools", amount=10000.0)
    a2 = _alloc(engine, category="training", amount=5000.0)
    engine.record_spend("org1", a1["id"], {"vendor_name": "V", "amount": 3000.0})
    stats = engine.get_budget_stats("org1")
    assert stats["total_allocated"] == pytest.approx(15000.0)
    assert stats["total_spent"] == pytest.approx(3000.0)
    assert stats["remaining"] == pytest.approx(12000.0)
    assert stats["utilization_pct"] == pytest.approx(20.0)


def test_get_budget_stats_by_category(engine):
    _alloc(engine, category="tools", amount=8000.0)
    _alloc(engine, category="personnel", amount=12000.0)
    stats = engine.get_budget_stats("org1")
    assert "tools" in stats["by_category"]
    assert "personnel" in stats["by_category"]
    assert stats["by_category"]["tools"]["allocated"] == pytest.approx(8000.0)


def test_get_budget_stats_fiscal_year_filter(engine):
    _alloc(engine, fiscal_year=2025, amount=5000.0)
    _alloc(engine, fiscal_year=2026, amount=10000.0)
    stats = engine.get_budget_stats("org1", fiscal_year=2025)
    assert stats["total_allocated"] == pytest.approx(5000.0)


def test_get_budget_stats_pending_count(engine):
    a = _alloc(engine)
    engine.record_spend("org1", a["id"], {"vendor_name": "V1", "amount": 100.0})
    engine.record_spend("org1", a["id"], {"vendor_name": "V2", "amount": 200.0})
    stats = engine.get_budget_stats("org1")
    assert stats["pending_transactions"] == 2


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_allocations(engine):
    _alloc(engine, org_id="org1")
    _alloc(engine, org_id="org2")
    assert len(engine.list_allocations("org1")) == 1
    assert len(engine.list_allocations("org2")) == 1


def test_org_isolation_transactions(engine):
    a1 = _alloc(engine, org_id="org1")
    a2 = _alloc(engine, org_id="org2")
    engine.record_spend("org1", a1["id"], {"vendor_name": "V", "amount": 100.0})
    assert len(engine.list_transactions("org1")) == 1
    assert len(engine.list_transactions("org2")) == 0


def test_org_isolation_roi(engine):
    engine.record_roi_assessment("org1", {
        "initiative_name": "X", "investment_amount": 1000.0, "estimated_risk_reduction": 5.0
    })
    assert len(engine.list_roi_assessments("org1")) == 1
    assert len(engine.list_roi_assessments("org2")) == 0


def test_org_isolation_stats(engine):
    _alloc(engine, org_id="org1", amount=10000.0)
    stats_org1 = engine.get_budget_stats("org1")
    stats_org2 = engine.get_budget_stats("org2")
    assert stats_org1["total_allocated"] == pytest.approx(10000.0)
    assert stats_org2["total_allocated"] == pytest.approx(0.0)
