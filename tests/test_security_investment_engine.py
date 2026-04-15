"""Tests for SecurityInvestmentEngine — 40 tests covering all methods.

Covers:
- Investment CRUD and lifecycle (planned→active→completed)
- ROI score computation (verified outcomes only)
- Budget set + spend + over_budget detection
- Portfolio summary (by_category, top_roi, counts)
- Budget utilization (remaining, over_budget)
- List filtering (status, category)
- Multi-tenant isolation (org_id)
- Validation errors (bad category, currency, outcome_type)
"""
from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.security_investment_engine import SecurityInvestmentEngine

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ORG = "org-si-test"
ORG2 = "org-si-other"


@pytest.fixture
def engine(tmp_path):
    return SecurityInvestmentEngine(db_path=str(tmp_path / "test_si.db"))


def _make_investment(engine, org=ORG, **kwargs):
    defaults = {
        "investment_name": "EDR Platform",
        "investment_category": "tools",
        "vendor": "AcmeSec",
        "amount": 50000.0,
        "currency": "USD",
        "start_date": "2025-01-01",
        "end_date": "2025-12-31",
    }
    defaults.update(kwargs)
    return engine.create_investment(org, **defaults)


# ---------------------------------------------------------------------------
# create_investment
# ---------------------------------------------------------------------------

class TestCreateInvestment:
    def test_returns_planned_status(self, engine):
        inv = _make_investment(engine)
        assert inv["status"] == "planned"

    def test_roi_score_starts_at_zero(self, engine):
        inv = _make_investment(engine)
        assert inv["roi_score"] == 0.0

    def test_risk_reduction_starts_at_zero(self, engine):
        inv = _make_investment(engine)
        assert inv["risk_reduction"] == 0.0

    def test_compliance_value_starts_at_zero(self, engine):
        inv = _make_investment(engine)
        assert inv["compliance_value"] == 0.0

    def test_id_is_set(self, engine):
        inv = _make_investment(engine)
        assert inv["id"] and len(inv["id"]) == 36

    def test_org_id_stored(self, engine):
        inv = _make_investment(engine, org=ORG)
        assert inv["org_id"] == ORG

    def test_invalid_category_raises(self, engine):
        with pytest.raises(ValueError, match="investment_category"):
            _make_investment(engine, investment_category="unknown-cat")

    def test_invalid_currency_raises(self, engine):
        with pytest.raises(ValueError, match="currency"):
            _make_investment(engine, currency="JPY")

    def test_all_valid_categories(self, engine):
        valid_cats = ["tools", "personnel", "training", "compliance",
                      "infrastructure", "consulting", "insurance", "R&D"]
        for cat in valid_cats:
            inv = _make_investment(engine, investment_name=f"Inv-{cat}",
                                   investment_category=cat)
            assert inv["investment_category"] == cat

    def test_all_valid_currencies(self, engine):
        for curr in ["USD", "EUR", "GBP", "AUD", "CAD"]:
            inv = _make_investment(engine, investment_name=f"Inv-{curr}", currency=curr)
            assert inv["currency"] == curr


# ---------------------------------------------------------------------------
# record_outcome + ROI computation
# ---------------------------------------------------------------------------

class TestRecordOutcome:
    def test_unverified_outcome_does_not_change_roi(self, engine):
        inv = _make_investment(engine, amount=10000.0)
        result = engine.record_outcome(
            investment_id=inv["id"],
            org_id=ORG,
            outcome_type="cost-avoidance",
            quantified_value=5000.0,
            verified=False,
        )
        assert result["roi_score_after"] == 0.0

    def test_verified_outcome_computes_roi(self, engine):
        inv = _make_investment(engine, amount=10000.0)
        result = engine.record_outcome(
            investment_id=inv["id"],
            org_id=ORG,
            outcome_type="cost-avoidance",
            quantified_value=5000.0,
            verified=True,
        )
        # ROI = 5000/10000 * 100 = 50.0
        assert result["roi_score_after"] == pytest.approx(50.0)

    def test_multiple_verified_outcomes_sum(self, engine):
        inv = _make_investment(engine, amount=10000.0)
        engine.record_outcome(inv["id"], ORG, "cost-avoidance", quantified_value=3000.0, verified=True)
        result = engine.record_outcome(inv["id"], ORG, "efficiency", quantified_value=2000.0, verified=True)
        # ROI = (3000+2000)/10000 * 100 = 50.0
        assert result["roi_score_after"] == pytest.approx(50.0)

    def test_mixed_verified_unverified_only_counts_verified(self, engine):
        inv = _make_investment(engine, amount=10000.0)
        engine.record_outcome(inv["id"], ORG, "efficiency", quantified_value=9000.0, verified=False)
        result = engine.record_outcome(inv["id"], ORG, "cost-avoidance", quantified_value=1000.0, verified=True)
        # only 1000 verified → ROI = 10.0
        assert result["roi_score_after"] == pytest.approx(10.0)

    def test_invalid_outcome_type_raises(self, engine):
        inv = _make_investment(engine)
        with pytest.raises(ValueError, match="outcome_type"):
            engine.record_outcome(inv["id"], ORG, "bad-type", quantified_value=100.0)

    def test_wrong_org_raises(self, engine):
        inv = _make_investment(engine, org=ORG)
        with pytest.raises(ValueError):
            engine.record_outcome(inv["id"], ORG2, "efficiency", quantified_value=100.0)

    def test_all_valid_outcome_types(self, engine):
        inv = _make_investment(engine, amount=10000.0)
        valid_types = ["cost-avoidance", "incident-reduction", "efficiency",
                       "compliance", "risk-reduction", "revenue-protection"]
        for ot in valid_types:
            r = engine.record_outcome(inv["id"], ORG, ot, quantified_value=100.0, verified=False)
            assert r["outcome_type"] == ot


# ---------------------------------------------------------------------------
# activate_investment / complete_investment
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_activate_sets_status(self, engine):
        inv = _make_investment(engine)
        updated = engine.activate_investment(inv["id"], ORG)
        assert updated["status"] == "active"

    def test_complete_sets_status(self, engine):
        inv = _make_investment(engine)
        engine.activate_investment(inv["id"], ORG)
        updated = engine.complete_investment(inv["id"], ORG)
        assert updated["status"] == "completed"

    def test_activate_wrong_org_no_change(self, engine):
        inv = _make_investment(engine, org=ORG)
        # Should raise because record not found for ORG2
        with pytest.raises(ValueError):
            engine.activate_investment(inv["id"], ORG2)


# ---------------------------------------------------------------------------
# set_budget / record_spend
# ---------------------------------------------------------------------------

class TestBudget:
    def test_set_budget_creates_record(self, engine):
        bud = engine.set_budget(ORG, "2025", "tools", 100000.0, "USD")
        assert bud["allocated"] == 100000.0
        assert bud["spent"] == 0.0

    def test_set_budget_upsert_updates_allocated(self, engine):
        engine.set_budget(ORG, "2025", "tools", 100000.0)
        bud = engine.set_budget(ORG, "2025", "tools", 200000.0)
        assert bud["allocated"] == 200000.0

    def test_record_spend_increments_spent(self, engine):
        engine.set_budget(ORG, "2025", "training", 50000.0)
        result = engine.record_spend(ORG, "2025", "training", 10000.0)
        assert result["spent"] == pytest.approx(10000.0)

    def test_record_spend_accumulates(self, engine):
        engine.set_budget(ORG, "2025", "personnel", 80000.0)
        engine.record_spend(ORG, "2025", "personnel", 20000.0)
        result = engine.record_spend(ORG, "2025", "personnel", 15000.0)
        assert result["spent"] == pytest.approx(35000.0)

    def test_over_budget_flag_false_when_within(self, engine):
        engine.set_budget(ORG, "2025", "compliance", 50000.0)
        result = engine.record_spend(ORG, "2025", "compliance", 40000.0)
        assert result["over_budget"] is False

    def test_over_budget_flag_true_when_exceeded(self, engine):
        engine.set_budget(ORG, "2025", "tools", 30000.0)
        result = engine.record_spend(ORG, "2025", "tools", 35000.0)
        assert result["over_budget"] is True

    def test_record_spend_missing_budget_raises(self, engine):
        with pytest.raises(ValueError):
            engine.record_spend(ORG, "2099", "tools", 1000.0)

    def test_invalid_category_raises(self, engine):
        with pytest.raises(ValueError, match="category"):
            engine.set_budget(ORG, "2025", "unknown", 10000.0)


# ---------------------------------------------------------------------------
# get_portfolio_summary
# ---------------------------------------------------------------------------

class TestPortfolioSummary:
    def test_empty_portfolio(self, engine):
        summary = engine.get_portfolio_summary(ORG)
        assert summary["total_investments"] == 0
        assert summary["total_invested"] == 0.0
        assert summary["top_roi_investments"] == []

    def test_counts_investments(self, engine):
        _make_investment(engine)
        _make_investment(engine, investment_name="SIEM", investment_category="tools")
        summary = engine.get_portfolio_summary(ORG)
        assert summary["total_investments"] == 2

    def test_active_completed_counts(self, engine):
        inv1 = _make_investment(engine)
        inv2 = _make_investment(engine, investment_name="Training", investment_category="training")
        engine.activate_investment(inv1["id"], ORG)
        engine.complete_investment(inv2["id"], ORG)
        summary = engine.get_portfolio_summary(ORG)
        assert summary["active_count"] == 1
        assert summary["completed_count"] == 1

    def test_top_roi_investments_sorted(self, engine):
        inv1 = _make_investment(engine, amount=1000.0, investment_name="Low ROI")
        inv2 = _make_investment(engine, amount=1000.0, investment_name="High ROI")
        engine.record_outcome(inv1["id"], ORG, "efficiency", quantified_value=100.0, verified=True)
        engine.record_outcome(inv2["id"], ORG, "efficiency", quantified_value=900.0, verified=True)
        summary = engine.get_portfolio_summary(ORG)
        rois = [t["roi_score"] for t in summary["top_roi_investments"]]
        assert rois == sorted(rois, reverse=True)

    def test_by_category_breakdown(self, engine):
        _make_investment(engine, investment_category="tools")
        _make_investment(engine, investment_name="Training2", investment_category="training")
        summary = engine.get_portfolio_summary(ORG)
        categories = [c["investment_category"] for c in summary["by_category"]]
        assert "tools" in categories
        assert "training" in categories

    def test_org_isolation_in_portfolio(self, engine):
        _make_investment(engine, org=ORG)
        _make_investment(engine, org=ORG2, investment_name="Other Inv")
        summary = engine.get_portfolio_summary(ORG)
        assert summary["total_investments"] == 1


# ---------------------------------------------------------------------------
# get_budget_utilization
# ---------------------------------------------------------------------------

class TestBudgetUtilization:
    def test_returns_all_categories_for_year(self, engine):
        engine.set_budget(ORG, "2025", "tools", 50000.0)
        engine.set_budget(ORG, "2025", "training", 20000.0)
        util = engine.get_budget_utilization(ORG, "2025")
        categories = [u["category"] for u in util]
        assert "tools" in categories
        assert "training" in categories

    def test_remaining_computed(self, engine):
        engine.set_budget(ORG, "2025", "personnel", 100000.0)
        engine.record_spend(ORG, "2025", "personnel", 30000.0)
        util = engine.get_budget_utilization(ORG, "2025")
        row = next(u for u in util if u["category"] == "personnel")
        assert row["remaining"] == pytest.approx(70000.0)

    def test_over_budget_in_utilization(self, engine):
        engine.set_budget(ORG, "2025", "consulting", 10000.0)
        engine.record_spend(ORG, "2025", "consulting", 15000.0)
        util = engine.get_budget_utilization(ORG, "2025")
        row = next(u for u in util if u["category"] == "consulting")
        assert row["over_budget"] is True

    def test_empty_year_returns_empty(self, engine):
        util = engine.get_budget_utilization(ORG, "1900")
        assert util == []


# ---------------------------------------------------------------------------
# list_investments
# ---------------------------------------------------------------------------

class TestListInvestments:
    def test_list_all(self, engine):
        _make_investment(engine)
        _make_investment(engine, investment_name="SIEM")
        assert len(engine.list_investments(ORG)) == 2

    def test_filter_by_status(self, engine):
        inv = _make_investment(engine)
        _make_investment(engine, investment_name="Other")
        engine.activate_investment(inv["id"], ORG)
        active = engine.list_investments(ORG, status="active")
        assert len(active) == 1
        assert active[0]["status"] == "active"

    def test_filter_by_category(self, engine):
        _make_investment(engine, investment_category="tools")
        _make_investment(engine, investment_name="Training", investment_category="training")
        tools = engine.list_investments(ORG, investment_category="tools")
        assert all(t["investment_category"] == "tools" for t in tools)

    def test_org_isolation(self, engine):
        _make_investment(engine, org=ORG)
        _make_investment(engine, org=ORG2, investment_name="Other Org")
        assert len(engine.list_investments(ORG)) == 1
        assert len(engine.list_investments(ORG2)) == 1
