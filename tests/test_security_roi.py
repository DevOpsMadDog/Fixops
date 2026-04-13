"""
Comprehensive tests for Security Investment ROI Calculator.

Tests cover:
- InvestmentCategory enum
- Investment and ROIMetric Pydantic models
- SecurityROI core engine (add, calculate, portfolio, breach, risk, recommend, budget, trend)
- Singleton accessor
- Router endpoints via FastAPI TestClient

Run with: python -m pytest tests/test_security_roi.py -v --timeout=15
"""

from __future__ import annotations

import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

# Add suite-core and suite-api to path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.security_roi import (
    IBM_AVG_BREACH_COST_USD,
    InvestmentCategory,
    Investment,
    ROIMetric,
    SecurityROI,
    get_security_roi,
    PONEMON_RISK_REDUCTION,
    PONEMON_INCIDENTS_PREVENTED_PER_100K,
    _compute_trend,
    _recommendation_rationale,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def engine() -> SecurityROI:
    """In-memory SecurityROI engine for isolated tests."""
    return SecurityROI(db_path=":memory:", org_id="test-org")


@pytest.fixture
def sample_investment() -> Investment:
    return Investment(
        name="SIEM Platform",
        category=InvestmentCategory.TOOLS,
        amount_usd=50_000.0,
        annual_cost=20_000.0,
        description="Enterprise SIEM for log aggregation and alerting",
        org_id="test-org",
    )


@pytest.fixture
def populated_engine(engine: SecurityROI) -> SecurityROI:
    """Engine pre-populated with one investment per category."""
    investments = [
        Investment(name="SIEM", category=InvestmentCategory.TOOLS,
                   amount_usd=50_000, annual_cost=20_000, org_id="test-org"),
        Investment(name="SOC Team", category=InvestmentCategory.PERSONNEL,
                   amount_usd=0, annual_cost=300_000, org_id="test-org"),
        Investment(name="Security Awareness", category=InvestmentCategory.TRAINING,
                   amount_usd=5_000, annual_cost=5_000, org_id="test-org"),
        Investment(name="Pentest", category=InvestmentCategory.CONSULTING,
                   amount_usd=30_000, annual_cost=0, org_id="test-org"),
        Investment(name="Cyber Policy", category=InvestmentCategory.INSURANCE,
                   amount_usd=0, annual_cost=15_000, org_id="test-org"),
        Investment(name="WAF + Firewall", category=InvestmentCategory.INFRASTRUCTURE,
                   amount_usd=80_000, annual_cost=10_000, org_id="test-org"),
    ]
    for inv in investments:
        engine.add_investment(inv)
    return engine


# ============================================================================
# InvestmentCategory enum tests
# ============================================================================


class TestInvestmentCategory:
    def test_all_values_exist(self) -> None:
        expected = {"TOOLS", "PERSONNEL", "TRAINING", "CONSULTING", "INSURANCE", "INFRASTRUCTURE"}
        assert {c.value for c in InvestmentCategory} == expected

    def test_string_enum(self) -> None:
        assert InvestmentCategory("TOOLS") == InvestmentCategory.TOOLS
        assert InvestmentCategory("PERSONNEL") == InvestmentCategory.PERSONNEL

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            InvestmentCategory("UNKNOWN")

    def test_six_categories(self) -> None:
        assert len(list(InvestmentCategory)) == 6


# ============================================================================
# Investment model tests
# ============================================================================


class TestInvestmentModel:
    def test_default_id_is_uuid(self, sample_investment: Investment) -> None:
        import uuid
        uuid.UUID(sample_investment.id)  # raises if not valid UUID

    def test_default_org_id(self) -> None:
        inv = Investment(name="Test", category=InvestmentCategory.TOOLS, amount_usd=1000, annual_cost=0)
        assert inv.org_id == "default"

    def test_fields_present(self, sample_investment: Investment) -> None:
        assert sample_investment.name == "SIEM Platform"
        assert sample_investment.category == InvestmentCategory.TOOLS
        assert sample_investment.amount_usd == 50_000.0
        assert sample_investment.annual_cost == 20_000.0

    def test_negative_amount_raises(self) -> None:
        with pytest.raises(Exception):
            Investment(name="Bad", category=InvestmentCategory.TOOLS, amount_usd=-1, annual_cost=0)

    def test_default_start_date_is_today(self) -> None:
        inv = Investment(name="T", category=InvestmentCategory.TRAINING, amount_usd=0, annual_cost=0)
        today = datetime.now(timezone.utc).date().isoformat()
        assert inv.start_date == today

    def test_model_dump(self, sample_investment: Investment) -> None:
        d = sample_investment.model_dump()
        assert "id" in d
        assert "category" in d
        assert "amount_usd" in d


# ============================================================================
# ROIMetric model tests
# ============================================================================


class TestROIMetricModel:
    def test_fields(self) -> None:
        m = ROIMetric(
            investment_id="abc",
            risk_reduction_pct=25.0,
            incidents_prevented=3.5,
            cost_avoidance_usd=1_200_000.0,
            time_saved_hours=500.0,
            roi_ratio=4.2,
        )
        assert m.investment_id == "abc"
        assert m.risk_reduction_pct == 25.0
        assert m.roi_ratio == 4.2

    def test_risk_reduction_bounds(self) -> None:
        with pytest.raises(Exception):
            ROIMetric(investment_id="x", risk_reduction_pct=101.0,
                      incidents_prevented=0, cost_avoidance_usd=0,
                      time_saved_hours=0, roi_ratio=0)

    def test_negative_incidents_raises(self) -> None:
        with pytest.raises(Exception):
            ROIMetric(investment_id="x", risk_reduction_pct=10.0,
                      incidents_prevented=-1, cost_avoidance_usd=0,
                      time_saved_hours=0, roi_ratio=0)


# ============================================================================
# SecurityROI.add_investment
# ============================================================================


class TestAddInvestment:
    def test_returns_investment(self, engine: SecurityROI, sample_investment: Investment) -> None:
        result = engine.add_investment(sample_investment)
        assert result.id == sample_investment.id
        assert result.name == "SIEM Platform"

    def test_persisted_in_db(self, engine: SecurityROI, sample_investment: Investment) -> None:
        engine.add_investment(sample_investment)
        with engine._lock:
            conn = engine._connect()
            row = conn.execute(
                "SELECT id FROM investments WHERE id = ?", (sample_investment.id,)
            ).fetchone()
            engine._close(conn)
        assert row is not None

    def test_multiple_investments(self, engine: SecurityROI) -> None:
        for i in range(5):
            inv = Investment(name=f"Tool-{i}", category=InvestmentCategory.TOOLS,
                             amount_usd=1000 * i, annual_cost=500, org_id="test-org")
            engine.add_investment(inv)

        with engine._lock:
            conn = engine._connect()
            count = conn.execute(
                "SELECT COUNT(*) FROM investments WHERE org_id = 'test-org'"
            ).fetchone()[0]
            engine._close(conn)
        assert count == 5

    def test_upsert_same_id(self, engine: SecurityROI, sample_investment: Investment) -> None:
        engine.add_investment(sample_investment)
        sample_investment.name = "Updated SIEM"
        engine.add_investment(sample_investment)
        with engine._lock:
            conn = engine._connect()
            count = conn.execute("SELECT COUNT(*) FROM investments").fetchone()[0]
            engine._close(conn)
        assert count == 1


# ============================================================================
# SecurityROI.calculate_roi
# ============================================================================


class TestCalculateROI:
    def test_returns_roi_metric(self, engine: SecurityROI, sample_investment: Investment) -> None:
        engine.add_investment(sample_investment)
        metric = engine.calculate_roi(sample_investment.id)
        assert isinstance(metric, ROIMetric)
        assert metric.investment_id == sample_investment.id

    def test_unknown_id_raises_value_error(self, engine: SecurityROI) -> None:
        with pytest.raises(ValueError, match="not found"):
            engine.calculate_roi("nonexistent-id")

    def test_risk_reduction_positive(self, engine: SecurityROI, sample_investment: Investment) -> None:
        engine.add_investment(sample_investment)
        metric = engine.calculate_roi(sample_investment.id)
        assert metric.risk_reduction_pct > 0.0

    def test_cost_avoidance_based_on_ibm_model(self, engine: SecurityROI, sample_investment: Investment) -> None:
        engine.add_investment(sample_investment)
        metric = engine.calculate_roi(sample_investment.id)
        # cost avoidance = risk_reduction_pct/100 * IBM_AVG_BREACH_COST_USD
        expected_fraction = PONEMON_RISK_REDUCTION["TOOLS"]
        expected_avoidance = expected_fraction * IBM_AVG_BREACH_COST_USD
        assert abs(metric.cost_avoidance_usd - expected_avoidance) < 1.0

    def test_roi_ratio_positive_for_positive_investment(
        self, engine: SecurityROI, sample_investment: Investment
    ) -> None:
        engine.add_investment(sample_investment)
        metric = engine.calculate_roi(sample_investment.id)
        assert metric.roi_ratio > 0.0

    def test_snapshot_persisted(self, engine: SecurityROI, sample_investment: Investment) -> None:
        engine.add_investment(sample_investment)
        engine.calculate_roi(sample_investment.id)
        with engine._lock:
            conn = engine._connect()
            count = conn.execute(
                "SELECT COUNT(*) FROM roi_snapshots WHERE investment_id = ?",
                (sample_investment.id,),
            ).fetchone()[0]
            engine._close(conn)
        assert count == 1

    def test_zero_cost_investment_roi_is_zero(self, engine: SecurityROI) -> None:
        inv = Investment(name="Free Tool", category=InvestmentCategory.TOOLS,
                         amount_usd=0, annual_cost=0, org_id="test-org")
        engine.add_investment(inv)
        metric = engine.calculate_roi(inv.id)
        assert metric.roi_ratio == 0.0

    def test_incidents_prevented_proportional_to_investment(self, engine: SecurityROI) -> None:
        small = Investment(name="Small", category=InvestmentCategory.TRAINING,
                           amount_usd=100_000, annual_cost=0, org_id="test-org")
        large = Investment(name="Large", category=InvestmentCategory.TRAINING,
                           amount_usd=500_000, annual_cost=0, org_id="test-org")
        engine.add_investment(small)
        engine.add_investment(large)
        m_small = engine.calculate_roi(small.id)
        m_large = engine.calculate_roi(large.id)
        assert m_large.incidents_prevented > m_small.incidents_prevented


# ============================================================================
# SecurityROI.get_portfolio_roi
# ============================================================================


class TestPortfolioROI:
    def test_empty_portfolio(self, engine: SecurityROI) -> None:
        result = engine.get_portfolio_roi("empty-org")
        assert result["total_investments"] == 0
        assert result["blended_roi_ratio"] == 0.0

    def test_populated_portfolio(self, populated_engine: SecurityROI) -> None:
        result = populated_engine.get_portfolio_roi("test-org")
        assert result["total_investments"] == 6
        assert result["total_cost_usd"] > 0
        assert result["total_cost_avoidance_usd"] > 0
        assert result["blended_roi_ratio"] > 0.0

    def test_sorted_by_roi_desc(self, populated_engine: SecurityROI) -> None:
        result = populated_engine.get_portfolio_roi("test-org")
        ratios = [i["roi_ratio"] for i in result["investments"]]
        assert ratios == sorted(ratios, reverse=True)

    def test_investments_list_has_expected_keys(self, populated_engine: SecurityROI) -> None:
        result = populated_engine.get_portfolio_roi("test-org")
        for inv in result["investments"]:
            assert "investment_id" in inv
            assert "name" in inv
            assert "category" in inv
            assert "roi_ratio" in inv
            assert "cost_avoidance_usd" in inv

    def test_total_cost_is_sum(self, engine: SecurityROI) -> None:
        a = Investment(name="A", category=InvestmentCategory.TOOLS,
                       amount_usd=10_000, annual_cost=5_000, org_id="test-org")
        b = Investment(name="B", category=InvestmentCategory.PERSONNEL,
                       amount_usd=0, annual_cost=100_000, org_id="test-org")
        engine.add_investment(a)
        engine.add_investment(b)
        result = engine.get_portfolio_roi("test-org")
        assert result["total_cost_usd"] == pytest.approx(115_000.0)


# ============================================================================
# SecurityROI.get_cost_of_breach_estimate
# ============================================================================


class TestBreachEstimate:
    def test_default_returns_ibm_avg(self, engine: SecurityROI) -> None:
        result = engine.get_cost_of_breach_estimate("test-org")
        assert result["estimated_breach_cost_usd"] >= IBM_AVG_BREACH_COST_USD

    def test_healthcare_multiplier_higher(self, engine: SecurityROI) -> None:
        default = engine.get_cost_of_breach_estimate("test-org", industry="default")
        healthcare = engine.get_cost_of_breach_estimate("test-org", industry="healthcare")
        assert healthcare["estimated_breach_cost_usd"] > default["estimated_breach_cost_usd"]

    def test_enterprise_higher_than_small(self, engine: SecurityROI) -> None:
        small = engine.get_cost_of_breach_estimate("test-org", org_size="small")
        enterprise = engine.get_cost_of_breach_estimate("test-org", org_size="enterprise")
        assert enterprise["estimated_breach_cost_usd"] > small["estimated_breach_cost_usd"]

    def test_model_field_present(self, engine: SecurityROI) -> None:
        result = engine.get_cost_of_breach_estimate("test-org")
        assert "IBM" in result["model"]

    def test_breach_lifecycle_days_correct(self, engine: SecurityROI) -> None:
        result = engine.get_cost_of_breach_estimate("test-org")
        assert result["breach_lifecycle_days"] == 277

    def test_record_based_cost_for_large_breach(self, engine: SecurityROI) -> None:
        # 1M records → record cost should exceed default base
        result = engine.get_cost_of_breach_estimate(
            "test-org", records_at_risk=1_000_000
        )
        record_cost = 1_000_000 * 165.0  # $165M
        assert result["estimated_breach_cost_usd"] == pytest.approx(record_cost)


# ============================================================================
# SecurityROI.get_risk_reduction
# ============================================================================


class TestRiskReduction:
    def test_no_investments_zero_reduction(self, engine: SecurityROI) -> None:
        result = engine.get_risk_reduction("empty-org")
        assert result["overall_risk_reduction_pct"] == 0.0

    def test_reduction_capped_at_85(self, engine: SecurityROI) -> None:
        # Add very large investments in all categories
        for cat in InvestmentCategory:
            inv = Investment(name=f"Massive {cat.value}", category=cat,
                             amount_usd=10_000_000, annual_cost=5_000_000, org_id="test-org")
            engine.add_investment(inv)
        result = engine.get_risk_reduction("test-org")
        assert result["overall_risk_reduction_pct"] <= 85.0

    def test_residual_risk_decreases_with_investment(self, engine: SecurityROI) -> None:
        result_empty = engine.get_risk_reduction("empty-org")
        # Add investment
        inv = Investment(name="SIEM", category=InvestmentCategory.TOOLS,
                         amount_usd=100_000, annual_cost=0, org_id="invest-org")
        engine.add_investment(inv)
        result_with = engine.get_risk_reduction("invest-org")
        assert result_with["overall_risk_reduction_pct"] > result_empty["overall_risk_reduction_pct"]

    def test_category_breakdown_present(self, populated_engine: SecurityROI) -> None:
        result = populated_engine.get_risk_reduction("test-org")
        assert "category_breakdown" in result
        assert len(result["category_breakdown"]) > 0

    def test_methodology_field(self, engine: SecurityROI) -> None:
        result = engine.get_risk_reduction("test-org")
        assert "Ponemon" in result["methodology"]


# ============================================================================
# SecurityROI.get_investment_recommendations
# ============================================================================


class TestRecommendations:
    def test_returns_all_categories(self, engine: SecurityROI) -> None:
        result = engine.get_investment_recommendations("test-org")
        cats = {r["category"] for r in result["recommendations"]}
        assert "TOOLS" in cats
        assert "PERSONNEL" in cats
        assert "TRAINING" in cats

    def test_sorted_by_priority_desc(self, engine: SecurityROI) -> None:
        result = engine.get_investment_recommendations("test-org")
        scores = [r["priority_score"] for r in result["recommendations"]]
        assert scores == sorted(scores, reverse=True)

    def test_gap_decreases_after_investment(self, engine: SecurityROI) -> None:
        before = engine.get_investment_recommendations("gap-org")
        tools_before = next(r for r in before["recommendations"] if r["category"] == "TOOLS")

        inv = Investment(name="Heavy SIEM", category=InvestmentCategory.TOOLS,
                         amount_usd=500_000, annual_cost=0, org_id="gap-org")
        engine.add_investment(inv)

        after = engine.get_investment_recommendations("gap-org")
        tools_after = next(r for r in after["recommendations"] if r["category"] == "TOOLS")
        assert tools_after["gap_pct"] < tools_before["gap_pct"]

    def test_recommendation_has_rationale(self, engine: SecurityROI) -> None:
        result = engine.get_investment_recommendations("test-org")
        for rec in result["recommendations"]:
            assert len(rec["rationale"]) > 10

    def test_methodology_field(self, engine: SecurityROI) -> None:
        result = engine.get_investment_recommendations("test-org")
        assert "methodology" in result


# ============================================================================
# SecurityROI.get_budget_utilization
# ============================================================================


class TestBudgetUtilization:
    def test_no_investments(self, engine: SecurityROI) -> None:
        result = engine.get_budget_utilization("empty-org", annual_budget_usd=500_000)
        assert result["total_spent_usd"] == 0.0
        assert result["utilization_pct"] == 0.0

    def test_utilization_pct_calculated(self, engine: SecurityROI) -> None:
        inv = Investment(name="SIEM", category=InvestmentCategory.TOOLS,
                         amount_usd=100_000, annual_cost=50_000, org_id="budget-org")
        engine.add_investment(inv)
        result = engine.get_budget_utilization("budget-org", annual_budget_usd=500_000)
        assert result["utilization_pct"] == pytest.approx(30.0)

    def test_no_budget_set_utilization_none(self, engine: SecurityROI) -> None:
        result = engine.get_budget_utilization("empty-org", annual_budget_usd=0)
        assert result["utilization_pct"] is None
        assert result["remaining_budget_usd"] is None

    def test_category_breakdown_present(self, populated_engine: SecurityROI) -> None:
        result = populated_engine.get_budget_utilization("test-org")
        assert len(result["category_breakdown"]) > 0

    def test_total_spent_is_sum_of_one_time_and_recurring(self, engine: SecurityROI) -> None:
        inv = Investment(name="T", category=InvestmentCategory.TOOLS,
                         amount_usd=40_000, annual_cost=10_000, org_id="sum-org")
        engine.add_investment(inv)
        result = engine.get_budget_utilization("sum-org")
        assert result["total_spent_usd"] == pytest.approx(50_000.0)
        assert result["total_one_time_usd"] == pytest.approx(40_000.0)
        assert result["total_recurring_usd"] == pytest.approx(10_000.0)


# ============================================================================
# SecurityROI.get_roi_trend
# ============================================================================


class TestROITrend:
    def test_empty_returns_no_data_points(self, engine: SecurityROI) -> None:
        result = engine.get_roi_trend("empty-org", months=6)
        assert result["data_points"] == []
        assert result["trend_direction"] == "insufficient_data"

    def test_months_clamped(self, engine: SecurityROI) -> None:
        result = engine.get_roi_trend("test-org", months=0)
        assert result["months_requested"] == 1
        result = engine.get_roi_trend("test-org", months=999)
        assert result["months_requested"] == 60

    def test_trend_present_after_roi_calculation(
        self, engine: SecurityROI, sample_investment: Investment
    ) -> None:
        engine.add_investment(sample_investment)
        engine.calculate_roi(sample_investment.id)
        result = engine.get_roi_trend("test-org", months=12)
        assert len(result["data_points"]) >= 1

    def test_data_point_has_expected_keys(
        self, engine: SecurityROI, sample_investment: Investment
    ) -> None:
        engine.add_investment(sample_investment)
        engine.calculate_roi(sample_investment.id)
        result = engine.get_roi_trend("test-org", months=12)
        if result["data_points"]:
            dp = result["data_points"][0]
            assert "month" in dp
            assert "avg_roi_ratio" in dp
            assert "total_cost_avoidance_usd" in dp
            assert "total_incidents_prevented" in dp


# ============================================================================
# Helper function tests
# ============================================================================


class TestHelpers:
    def test_compute_trend_improving(self) -> None:
        assert _compute_trend([1.0, 1.5, 2.0, 3.0]) == "improving"

    def test_compute_trend_degrading(self) -> None:
        assert _compute_trend([3.0, 2.5, 2.0, 1.0]) == "degrading"

    def test_compute_trend_stable(self) -> None:
        assert _compute_trend([2.0, 2.01, 1.99, 2.0]) == "stable"

    def test_compute_trend_insufficient(self) -> None:
        assert _compute_trend([]) == "insufficient_data"
        assert _compute_trend([1.0]) == "insufficient_data"

    def test_recommendation_rationale_for_each_category(self) -> None:
        for cat in ["TOOLS", "PERSONNEL", "TRAINING", "CONSULTING", "INSURANCE", "INFRASTRUCTURE"]:
            rationale = _recommendation_rationale(cat, 0.05)
            assert len(rationale) > 20

    def test_recommendation_rationale_large_gap_mention(self) -> None:
        rationale = _recommendation_rationale("TOOLS", 0.20)
        assert "20%" in rationale or "below" in rationale


# ============================================================================
# Singleton tests
# ============================================================================


class TestSingleton:
    def test_get_security_roi_returns_instance(self) -> None:
        engine = get_security_roi(db_path=":memory:")
        assert isinstance(engine, SecurityROI)

    def test_singleton_same_instance(self) -> None:
        a = get_security_roi(db_path=":memory:")
        b = get_security_roi(db_path=":memory:")
        assert a is b


# ============================================================================
# Constants validation
# ============================================================================


class TestConstants:
    def test_ibm_breach_cost(self) -> None:
        assert IBM_AVG_BREACH_COST_USD == 4_450_000.0

    def test_ponemon_risk_reduction_all_categories(self) -> None:
        for cat in InvestmentCategory:
            assert cat.value in PONEMON_RISK_REDUCTION
            assert 0.0 < PONEMON_RISK_REDUCTION[cat.value] <= 1.0

    def test_ponemon_incidents_prevented_all_categories(self) -> None:
        for cat in InvestmentCategory:
            assert cat.value in PONEMON_INCIDENTS_PREVENTED_PER_100K
            assert PONEMON_INCIDENTS_PREVENTED_PER_100K[cat.value] > 0
