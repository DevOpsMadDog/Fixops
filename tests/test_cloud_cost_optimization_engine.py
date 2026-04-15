"""Tests for CloudCostOptimizationEngine.

Covers: tool registration annual_cost=monthly*12, utilization clamping,
optimization lifecycle, ROI formula (incidents_prevented*avg_cost - annual_cost)
/ annual_cost*100, underutilized threshold, portfolio SUM aggregation,
cost_per_risk ordering, org isolation.
"""

from __future__ import annotations

import pytest

from core.cloud_cost_optimization_engine import CloudCostOptimizationEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "cco_test.db")
    return CloudCostOptimizationEngine(db_path=db)


@pytest.fixture
def org():
    return "org-cco-001"


@pytest.fixture
def org2():
    return "org-cco-002"


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

class TestRegisterTool:
    def test_register_basic(self, engine, org):
        t = engine.register_tool(org, "Splunk SIEM")
        assert t["id"]
        assert t["org_id"] == org
        assert t["tool_name"] == "Splunk SIEM"
        assert t["tool_category"] == "detection"
        assert t["cloud_provider"] == "multi-cloud"
        assert t["monthly_cost"] == 0.0
        assert t["annual_cost"] == 0.0
        assert t["utilization_pct"] == 0.0
        assert t["risk_coverage"] == "[]"
        assert t["status"] == "active"

    def test_annual_cost_equals_monthly_times_12(self, engine, org):
        t = engine.register_tool(org, "Tool", monthly_cost=1000.0)
        assert t["annual_cost"] == 12000.0

    def test_register_all_fields(self, engine, org):
        t = engine.register_tool(
            org, "CrowdStrike", tool_category="endpoint",
            vendor="CrowdStrike Inc", cloud_provider="saas",
            monthly_cost=500.0, licenses=100,
        )
        assert t["tool_category"] == "endpoint"
        assert t["vendor"] == "CrowdStrike Inc"
        assert t["cloud_provider"] == "saas"
        assert t["licenses"] == 100
        assert t["annual_cost"] == 6000.0

    def test_invalid_tool_category(self, engine, org):
        with pytest.raises(ValueError, match="tool_category"):
            engine.register_tool(org, "Tool", tool_category="invalid-cat")

    def test_invalid_cloud_provider(self, engine, org):
        with pytest.raises(ValueError, match="cloud_provider"):
            engine.register_tool(org, "Tool", cloud_provider="oracle-cloud")

    def test_negative_monthly_cost(self, engine, org):
        with pytest.raises(ValueError, match="monthly_cost"):
            engine.register_tool(org, "Tool", monthly_cost=-100.0)

    def test_all_valid_tool_categories(self, engine, org):
        cats = ["detection", "prevention", "response", "compliance", "identity",
                "network", "endpoint", "cloud", "data", "governance"]
        for cat in cats:
            t = engine.register_tool(org, f"Tool-{cat}", tool_category=cat)
            assert t["tool_category"] == cat

    def test_all_valid_cloud_providers(self, engine, org):
        for provider in ["aws", "azure", "gcp", "multi-cloud", "on-prem", "saas"]:
            t = engine.register_tool(org, f"Tool-{provider}", cloud_provider=provider)
            assert t["cloud_provider"] == provider


# ---------------------------------------------------------------------------
# List tools
# ---------------------------------------------------------------------------

class TestListTools:
    def test_list_empty(self, engine, org):
        assert engine.list_tools(org) == []

    def test_list_multiple(self, engine, org):
        engine.register_tool(org, "T1")
        engine.register_tool(org, "T2")
        assert len(engine.list_tools(org)) == 2

    def test_list_org_isolation(self, engine, org, org2):
        engine.register_tool(org, "T1")
        engine.register_tool(org2, "T2")
        assert len(engine.list_tools(org)) == 1
        assert len(engine.list_tools(org2)) == 1

    def test_list_ordered_by_monthly_cost_desc(self, engine, org):
        engine.register_tool(org, "Cheap", monthly_cost=100.0)
        engine.register_tool(org, "Expensive", monthly_cost=1000.0)
        tools = engine.list_tools(org)
        assert tools[0]["monthly_cost"] >= tools[1]["monthly_cost"]


# ---------------------------------------------------------------------------
# Utilization update
# ---------------------------------------------------------------------------

class TestUpdateUtilization:
    def test_update_utilization(self, engine, org):
        t = engine.register_tool(org, "Tool")
        updated = engine.update_utilization(t["id"], org, 75.0, ["endpoint", "network"])
        assert updated["utilization_pct"] == 75.0

    def test_utilization_clamped_high(self, engine, org):
        t = engine.register_tool(org, "Tool")
        updated = engine.update_utilization(t["id"], org, 150.0)
        assert updated["utilization_pct"] == 100.0

    def test_utilization_clamped_low(self, engine, org):
        t = engine.register_tool(org, "Tool")
        updated = engine.update_utilization(t["id"], org, -20.0)
        assert updated["utilization_pct"] == 0.0

    def test_update_utilization_not_found(self, engine, org):
        with pytest.raises(KeyError):
            engine.update_utilization("bad-id", org, 50.0)

    def test_update_utilization_org_isolation(self, engine, org, org2):
        t = engine.register_tool(org, "Tool")
        with pytest.raises(KeyError):
            engine.update_utilization(t["id"], org2, 50.0)


# ---------------------------------------------------------------------------
# Optimizations
# ---------------------------------------------------------------------------

class TestOptimizations:
    def test_add_optimization(self, engine, org):
        t = engine.register_tool(org, "Tool", monthly_cost=500.0)
        opt = engine.add_optimization(t["id"], org, "right-sizing", "Reduce instances", 200.0)
        assert opt["optimization_type"] == "right-sizing"
        assert opt["status"] == "identified"
        assert opt["actual_savings"] == 0.0
        assert opt["estimated_savings"] == 200.0

    def test_invalid_optimization_type(self, engine, org):
        t = engine.register_tool(org, "Tool")
        with pytest.raises(ValueError, match="optimization_type"):
            engine.add_optimization(t["id"], org, "bad-type", "desc", 100.0)

    def test_add_optimization_tool_not_found(self, engine, org):
        with pytest.raises(KeyError):
            engine.add_optimization("bad-id", org, "right-sizing")

    def test_implement_optimization(self, engine, org):
        t = engine.register_tool(org, "Tool", monthly_cost=500.0)
        opt = engine.add_optimization(t["id"], org, "consolidation", "Merge licenses", 300.0)
        result = engine.implement_optimization(opt["id"], org, actual_savings=280.0)
        assert result["status"] == "implemented"
        assert result["actual_savings"] == 280.0
        assert result["implemented_at"] is not None

    def test_implement_optimization_not_found(self, engine, org):
        with pytest.raises(KeyError):
            engine.implement_optimization("bad-id", org, 100.0)

    def test_negative_actual_savings_rejected(self, engine, org):
        t = engine.register_tool(org, "Tool")
        opt = engine.add_optimization(t["id"], org, "right-sizing", estimated_savings=100.0)
        with pytest.raises(ValueError):
            engine.implement_optimization(opt["id"], org, -50.0)

    def test_all_valid_optimization_types(self, engine, org):
        t = engine.register_tool(org, "Tool")
        for ot in ["right-sizing", "license-reduction", "contract-renegotiation",
                   "consolidation", "elimination", "migration"]:
            opt = engine.add_optimization(t["id"], org, ot)
            assert opt["optimization_type"] == ot


# ---------------------------------------------------------------------------
# ROI assessments
# ---------------------------------------------------------------------------

class TestROIAssessments:
    def test_roi_formula(self, engine, org):
        # Tool annual = 12000; 10 incidents * 5000 each = 50000
        # ROI = (50000 - 12000) / 12000 * 100 = 316.67
        t = engine.register_tool(org, "Tool", monthly_cost=1000.0)
        ra = engine.add_roi_assessment(
            t["id"], org, "Q1-2026",
            incidents_prevented=10,
            avg_incident_cost=5000.0,
            risk_reduction_pct=40.0,
        )
        expected_roi = (10 * 5000 - 12000) / 12000 * 100
        assert abs(ra["roi_pct"] - expected_roi) < 0.01

    def test_roi_negative_when_costs_exceed_benefit(self, engine, org):
        # Tool annual = 120000; 1 incident * 1000 each = 1000
        # ROI = (1000 - 120000) / 120000 * 100 < 0
        t = engine.register_tool(org, "ExpensiveTool", monthly_cost=10000.0)
        ra = engine.add_roi_assessment(
            t["id"], org, "Q1-2026",
            incidents_prevented=1,
            avg_incident_cost=1000.0,
            risk_reduction_pct=5.0,
        )
        assert ra["roi_pct"] < 0

    def test_risk_reduction_clamped(self, engine, org):
        t = engine.register_tool(org, "Tool", monthly_cost=100.0)
        ra = engine.add_roi_assessment(
            t["id"], org, "Q1", incidents_prevented=5,
            avg_incident_cost=1000.0, risk_reduction_pct=150.0,
        )
        assert ra["risk_reduction_pct"] == 100.0

    def test_roi_tool_not_found(self, engine, org):
        with pytest.raises(KeyError):
            engine.add_roi_assessment("bad-id", org, "Q1", 5, 1000.0, 30.0)

    def test_zero_annual_cost_uses_max_1(self, engine, org):
        # Tool with 0 annual cost — denominator should not blow up
        t = engine.register_tool(org, "FreeTool", monthly_cost=0.0)
        ra = engine.add_roi_assessment(
            t["id"], org, "Q1", incidents_prevented=3,
            avg_incident_cost=1000.0, risk_reduction_pct=20.0,
        )
        # (3000 - 0) / max(1, 0) * 100 = 300000
        assert ra["roi_pct"] == pytest.approx(300000.0, rel=1e-3)


# ---------------------------------------------------------------------------
# get_tool_roi
# ---------------------------------------------------------------------------

class TestGetToolROI:
    def test_get_tool_roi_structure(self, engine, org):
        t = engine.register_tool(org, "Tool", monthly_cost=500.0)
        opt = engine.add_optimization(t["id"], org, "right-sizing", estimated_savings=100.0)
        engine.implement_optimization(opt["id"], org, actual_savings=90.0)
        engine.add_roi_assessment(t["id"], org, "Q1", 5, 2000.0, 30.0)
        roi = engine.get_tool_roi(t["id"], org)
        assert roi["tool_name"] == "Tool"
        assert len(roi["assessments"]) == 1
        assert len(roi["optimizations"]) == 1
        assert roi["total_savings"] == 90.0

    def test_get_tool_roi_not_found(self, engine, org):
        with pytest.raises(KeyError):
            engine.get_tool_roi("bad-id", org)

    def test_get_tool_roi_org_isolation(self, engine, org, org2):
        t = engine.register_tool(org, "Tool")
        with pytest.raises(KeyError):
            engine.get_tool_roi(t["id"], org2)

    def test_total_savings_only_implemented(self, engine, org):
        t = engine.register_tool(org, "Tool", monthly_cost=500.0)
        opt1 = engine.add_optimization(t["id"], org, "right-sizing", estimated_savings=200.0)
        opt2 = engine.add_optimization(t["id"], org, "consolidation", estimated_savings=300.0)
        engine.implement_optimization(opt1["id"], org, actual_savings=180.0)
        # opt2 stays 'identified'
        roi = engine.get_tool_roi(t["id"], org)
        assert roi["total_savings"] == 180.0  # only opt1 counts


# ---------------------------------------------------------------------------
# Underutilized tools
# ---------------------------------------------------------------------------

class TestUnderutilizedTools:
    def test_underutilized_default_threshold(self, engine, org):
        t1 = engine.register_tool(org, "Underused", monthly_cost=1000.0)
        t2 = engine.register_tool(org, "WellUsed", monthly_cost=500.0)
        engine.update_utilization(t1["id"], org, 20.0)
        engine.update_utilization(t2["id"], org, 80.0)
        result = engine.get_underutilized_tools(org)
        names = [r["tool_name"] for r in result]
        assert "Underused" in names
        assert "WellUsed" not in names

    def test_underutilized_custom_threshold(self, engine, org):
        t1 = engine.register_tool(org, "T1", monthly_cost=100.0)
        t2 = engine.register_tool(org, "T2", monthly_cost=200.0)
        engine.update_utilization(t1["id"], org, 40.0)
        engine.update_utilization(t2["id"], org, 60.0)
        result = engine.get_underutilized_tools(org, max_utilization=50.0)
        names = [r["tool_name"] for r in result]
        assert "T1" in names
        assert "T2" not in names

    def test_underutilized_ordered_by_monthly_cost_desc(self, engine, org):
        for name, cost in [("Cheap", 100.0), ("Mid", 500.0), ("Costly", 1000.0)]:
            t = engine.register_tool(org, name, monthly_cost=cost)
            engine.update_utilization(t["id"], org, 10.0)
        result = engine.get_underutilized_tools(org)
        costs = [r["monthly_cost"] for r in result]
        assert costs == sorted(costs, reverse=True)

    def test_underutilized_org_isolation(self, engine, org, org2):
        t = engine.register_tool(org, "Tool", monthly_cost=100.0)
        engine.update_utilization(t["id"], org, 5.0)
        result = engine.get_underutilized_tools(org2)
        assert result == []

    def test_at_exact_threshold_included(self, engine, org):
        t = engine.register_tool(org, "ExactTool", monthly_cost=100.0)
        engine.update_utilization(t["id"], org, 30.0)
        result = engine.get_underutilized_tools(org, max_utilization=30.0)
        assert any(r["tool_name"] == "ExactTool" for r in result)


# ---------------------------------------------------------------------------
# Portfolio summary
# ---------------------------------------------------------------------------

class TestPortfolioSummary:
    def test_empty_portfolio(self, engine, org):
        s = engine.get_portfolio_summary(org)
        assert s["total_tools"] == 0
        assert s["total_monthly_cost"] == 0.0
        assert s["total_annual_cost"] == 0.0
        assert s["high_roi_tools"] == 0

    def test_portfolio_cost_aggregation(self, engine, org):
        engine.register_tool(org, "T1", monthly_cost=1000.0, tool_category="detection")
        engine.register_tool(org, "T2", monthly_cost=500.0, tool_category="detection")
        engine.register_tool(org, "T3", monthly_cost=250.0, tool_category="endpoint")
        s = engine.get_portfolio_summary(org)
        assert s["total_tools"] == 3
        assert s["total_monthly_cost"] == 1750.0
        assert s["total_annual_cost"] == 21000.0

    def test_portfolio_by_category(self, engine, org):
        engine.register_tool(org, "T1", monthly_cost=1000.0, tool_category="detection")
        engine.register_tool(org, "T2", monthly_cost=500.0, tool_category="detection")
        engine.register_tool(org, "T3", monthly_cost=250.0, tool_category="endpoint")
        s = engine.get_portfolio_summary(org)
        assert s["by_category"]["detection"] == 1500.0
        assert s["by_category"]["endpoint"] == 250.0

    def test_portfolio_potential_savings(self, engine, org):
        t = engine.register_tool(org, "T1", monthly_cost=1000.0)
        engine.add_optimization(t["id"], org, "right-sizing", estimated_savings=200.0)
        engine.add_optimization(t["id"], org, "consolidation", estimated_savings=100.0)
        s = engine.get_portfolio_summary(org)
        assert s["potential_savings"] == 300.0

    def test_portfolio_realized_savings(self, engine, org):
        t = engine.register_tool(org, "T1", monthly_cost=1000.0)
        opt = engine.add_optimization(t["id"], org, "right-sizing", estimated_savings=200.0)
        engine.implement_optimization(opt["id"], org, actual_savings=180.0)
        s = engine.get_portfolio_summary(org)
        assert s["realized_savings"] == 180.0

    def test_portfolio_high_roi_tools(self, engine, org):
        t1 = engine.register_tool(org, "T1", monthly_cost=100.0)
        t2 = engine.register_tool(org, "T2", monthly_cost=5000.0)
        # T1: (10*5000 - 1200) / 1200 * 100 = huge ROI > 100
        engine.add_roi_assessment(t1["id"], org, "Q1", 10, 5000.0, 50.0)
        # T2: (1*100 - 60000) / 60000 * 100 = negative ROI
        engine.add_roi_assessment(t2["id"], org, "Q1", 1, 100.0, 5.0)
        s = engine.get_portfolio_summary(org)
        assert s["high_roi_tools"] == 1

    def test_portfolio_org_isolation(self, engine, org, org2):
        engine.register_tool(org, "T1", monthly_cost=1000.0)
        engine.register_tool(org2, "T2", monthly_cost=2000.0)
        s1 = engine.get_portfolio_summary(org)
        s2 = engine.get_portfolio_summary(org2)
        assert s1["total_monthly_cost"] == 1000.0
        assert s2["total_monthly_cost"] == 2000.0


# ---------------------------------------------------------------------------
# Cost per risk
# ---------------------------------------------------------------------------

class TestCostPerRisk:
    def test_cost_per_risk_ordering(self, engine, org):
        t1 = engine.register_tool(org, "Efficient", monthly_cost=100.0)
        t2 = engine.register_tool(org, "Expensive", monthly_cost=500.0)
        # T1: annual=1200, risk=60 → cost_per_risk = 20
        engine.add_roi_assessment(t1["id"], org, "Q1", 5, 1000.0, 60.0)
        # T2: annual=6000, risk=20 → cost_per_risk = 300
        engine.add_roi_assessment(t2["id"], org, "Q1", 5, 1000.0, 20.0)
        result = engine.get_cost_per_risk(org)
        assert result[0]["tool_name"] == "Efficient"
        assert result[0]["cost_per_risk_pct"] < result[1]["cost_per_risk_pct"]

    def test_cost_per_risk_no_assessment(self, engine, org):
        engine.register_tool(org, "NoAssessment", monthly_cost=500.0)
        result = engine.get_cost_per_risk(org)
        assert len(result) == 1
        # No assessment means risk_reduction_pct=0 → cost_per_risk = annual / 1
        assert result[0]["risk_reduction_pct"] == 0.0

    def test_cost_per_risk_org_isolation(self, engine, org, org2):
        t = engine.register_tool(org, "T1", monthly_cost=100.0)
        engine.add_roi_assessment(t["id"], org, "Q1", 5, 1000.0, 30.0)
        result = engine.get_cost_per_risk(org2)
        assert result == []

    def test_cost_per_risk_uses_latest_assessment(self, engine, org):
        t = engine.register_tool(org, "Tool", monthly_cost=100.0)
        engine.add_roi_assessment(t["id"], org, "Q1", 1, 100.0, 10.0)
        engine.add_roi_assessment(t["id"], org, "Q2", 5, 5000.0, 80.0)  # latest
        result = engine.get_cost_per_risk(org)
        assert result[0]["risk_reduction_pct"] == 80.0
