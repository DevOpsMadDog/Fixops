"""Tests for RiskQuantificationEngineV2 — FAIR methodology engine.

Covers: SLE=asset_value*exposure_factor, ALE=SLE*ARO, exposure_factor clamp,
ALE risk_level thresholds, ROI formula, residual_ale, control_effectiveness=MAX,
org isolation, snapshot, portfolio summary, history, ROI analysis.
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from core.risk_quantification_engine_v2 import RiskQuantificationEngineV2


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "rqv2_test.db")
    return RiskQuantificationEngineV2(db_path=db)


# ---------------------------------------------------------------------------
# Scenario creation — FAIR calculations
# ---------------------------------------------------------------------------

class TestCreateScenario:
    def test_sle_is_asset_value_times_exposure_factor(self, engine):
        sc = engine.create_scenario("org1", "Test", "Server", "APT", "malware",
                                    asset_value=200_000, exposure_factor=0.4,
                                    annual_rate_occurrence=1.0)
        assert sc["single_loss_expectancy"] == pytest.approx(80_000.0)

    def test_ale_is_sle_times_aro(self, engine):
        sc = engine.create_scenario("org1", "Test", "Server", "APT", "malware",
                                    asset_value=100_000, exposure_factor=0.5,
                                    annual_rate_occurrence=2.0)
        assert sc["single_loss_expectancy"] == pytest.approx(50_000.0)
        assert sc["annual_loss_expectancy"] == pytest.approx(100_000.0)

    def test_initial_control_effectiveness_zero(self, engine):
        sc = engine.create_scenario("org1", "Test", "DB", "Insider", "insider",
                                    asset_value=500_000, exposure_factor=0.3,
                                    annual_rate_occurrence=0.5)
        assert sc["control_effectiveness"] == 0.0

    def test_initial_residual_ale_equals_ale(self, engine):
        sc = engine.create_scenario("org1", "Test", "App", "Criminal", "phishing",
                                    asset_value=100_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        assert sc["residual_ale"] == pytest.approx(sc["annual_loss_expectancy"])

    def test_exposure_factor_clamped_to_zero(self, engine):
        sc = engine.create_scenario("org1", "Test", "Asset", "Actor", "malware",
                                    asset_value=100_000, exposure_factor=-0.5,
                                    annual_rate_occurrence=1.0)
        assert sc["exposure_factor"] == 0.0
        assert sc["single_loss_expectancy"] == 0.0

    def test_exposure_factor_clamped_to_one(self, engine):
        sc = engine.create_scenario("org1", "Test", "Asset", "Actor", "ransomware",
                                    asset_value=50_000, exposure_factor=2.0,
                                    annual_rate_occurrence=1.0)
        assert sc["exposure_factor"] == 1.0
        assert sc["single_loss_expectancy"] == pytest.approx(50_000.0)

    def test_risk_level_critical_at_1m(self, engine):
        sc = engine.create_scenario("org1", "Critical", "DC", "Nation", "ransomware",
                                    asset_value=2_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        assert sc["risk_level"] == "critical"

    def test_risk_level_high_at_100k(self, engine):
        sc = engine.create_scenario("org1", "High", "App", "Criminal", "malware",
                                    asset_value=200_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        assert sc["risk_level"] == "high"

    def test_risk_level_medium_at_10k(self, engine):
        sc = engine.create_scenario("org1", "Med", "Asset", "Script", "phishing",
                                    asset_value=50_000, exposure_factor=0.4,
                                    annual_rate_occurrence=1.0)
        # SLE=20000, ALE=20000 → high
        # Use lower values: 20000 exposure 0.5 aro 1 → SLE=10000 ALE=10000 → medium
        sc2 = engine.create_scenario("org1", "Med2", "Asset", "Script", "phishing",
                                     asset_value=20_000, exposure_factor=0.5,
                                     annual_rate_occurrence=1.0)
        assert sc2["risk_level"] == "medium"

    def test_risk_level_low_below_10k(self, engine):
        sc = engine.create_scenario("org1", "Low", "Laptop", "Opp", "physical",
                                    asset_value=5_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        assert sc["risk_level"] == "low"

    def test_risk_level_boundary_exactly_1m_is_critical(self, engine):
        sc = engine.create_scenario("org1", "Boundary", "Asset", "Actor", "ddos",
                                    asset_value=1_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        assert sc["risk_level"] == "critical"

    def test_risk_level_boundary_exactly_100k_is_high(self, engine):
        sc = engine.create_scenario("org1", "Boundary100k", "Asset", "Actor", "ddos",
                                    asset_value=100_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        assert sc["risk_level"] == "high"

    def test_risk_level_boundary_exactly_10k_is_medium(self, engine):
        sc = engine.create_scenario("org1", "Boundary10k", "Asset", "Actor", "ddos",
                                    asset_value=10_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        assert sc["risk_level"] == "medium"

    def test_scenario_has_id_and_org_id(self, engine):
        sc = engine.create_scenario("orgX", "S", "A", "T", "insider",
                                    asset_value=10_000, exposure_factor=0.5,
                                    annual_rate_occurrence=1.0)
        assert sc["id"]
        assert sc["org_id"] == "orgX"

    def test_zero_asset_value_gives_zero_ale(self, engine):
        sc = engine.create_scenario("org1", "Zero", "Asset", "Actor", "system_failure",
                                    asset_value=0, exposure_factor=0.5,
                                    annual_rate_occurrence=10.0)
        assert sc["annual_loss_expectancy"] == 0.0
        assert sc["risk_level"] == "low"


# ---------------------------------------------------------------------------
# Add control — ROI and residual_ale
# ---------------------------------------------------------------------------

class TestAddControl:
    def test_roi_formula(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "malware",
                                    asset_value=1_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        # ALE=1_000_000, effectiveness=50%, implementation_cost=100_000, annual_cost=10_000
        # risk_reduction = 1_000_000 * 0.5 = 500_000
        # roi = (500_000 - 10_000) / 100_000 * 100 = 490%
        ctrl = engine.add_control(sc["id"], "org1", "Firewall", "preventive",
                                  implementation_cost=100_000, annual_cost=10_000,
                                  effectiveness_pct=50.0)
        assert ctrl["roi"] == pytest.approx(490.0)
        assert ctrl["recommended"] == 1

    def test_negative_roi_not_recommended(self, engine):
        sc = engine.create_scenario("org1", "SC2", "Asset", "Actor", "ddos",
                                    asset_value=10_000, exposure_factor=0.1,
                                    annual_rate_occurrence=1.0)
        # ALE=1000, effectiveness=10%, risk_reduction=100
        # annual_cost=5000, implementation_cost=10_000
        # roi = (100 - 5000) / 10_000 * 100 = -49%
        ctrl = engine.add_control(sc["id"], "org1", "ExpensiveCtrl", "preventive",
                                  implementation_cost=10_000, annual_cost=5_000,
                                  effectiveness_pct=10.0)
        assert ctrl["roi"] < 0
        assert ctrl["recommended"] == 0

    def test_control_effectiveness_max_recomputes_residual(self, engine):
        sc = engine.create_scenario("org1", "SC3", "Asset", "Actor", "ransomware",
                                    asset_value=1_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        ale = sc["annual_loss_expectancy"]
        # Add two controls: 30% and 60%
        engine.add_control(sc["id"], "org1", "Ctrl30", "detective",
                           implementation_cost=10_000, annual_cost=1_000,
                           effectiveness_pct=30.0)
        engine.add_control(sc["id"], "org1", "Ctrl60", "preventive",
                           implementation_cost=20_000, annual_cost=2_000,
                           effectiveness_pct=60.0)
        detail = engine.get_scenario_detail(sc["id"], "org1")
        # control_effectiveness = MAX = 60
        assert detail["control_effectiveness"] == pytest.approx(60.0)
        # residual_ale = ALE * (1 - 60/100)
        assert detail["residual_ale"] == pytest.approx(ale * 0.4)

    def test_effectiveness_pct_clamped_to_100(self, engine):
        sc = engine.create_scenario("org1", "SC4", "Asset", "Actor", "insider",
                                    asset_value=500_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        ctrl = engine.add_control(sc["id"], "org1", "SuperCtrl", "preventive",
                                  implementation_cost=1_000, annual_cost=100,
                                  effectiveness_pct=150.0)
        assert ctrl["effectiveness_pct"] == 100.0

    def test_effectiveness_pct_clamped_to_zero(self, engine):
        sc = engine.create_scenario("org1", "SC5", "Asset", "Actor", "phishing",
                                    asset_value=100_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        ctrl = engine.add_control(sc["id"], "org1", "ZeroCtrl", "corrective",
                                  implementation_cost=1_000, annual_cost=100,
                                  effectiveness_pct=-10.0)
        assert ctrl["effectiveness_pct"] == 0.0

    def test_zero_implementation_cost_uses_max_1_denominator(self, engine):
        sc = engine.create_scenario("org1", "SC6", "Asset", "Actor", "ddos",
                                    asset_value=100_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        # implementation_cost=0 → denom = max(1, 0) = 1
        ctrl = engine.add_control(sc["id"], "org1", "FreeCtrl", "preventive",
                                  implementation_cost=0, annual_cost=0,
                                  effectiveness_pct=50.0)
        # roi = (100_000 * 0.5 - 0) / 1 * 100 = 5_000_000
        assert ctrl["roi"] == pytest.approx(5_000_000.0)

    def test_add_control_unknown_scenario_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.add_control("nonexistent", "org1", "Ctrl", "preventive",
                               implementation_cost=0, annual_cost=0, effectiveness_pct=0)

    def test_org_isolation_add_control(self, engine):
        sc = engine.create_scenario("org_a", "SC", "Asset", "Actor", "malware",
                                    asset_value=100_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        with pytest.raises(ValueError):
            engine.add_control(sc["id"], "org_b", "Ctrl", "preventive",
                               implementation_cost=0, annual_cost=0, effectiveness_pct=10)


# ---------------------------------------------------------------------------
# Update rates
# ---------------------------------------------------------------------------

class TestUpdateRates:
    def test_update_asset_value_recomputes_sle_ale(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "malware",
                                    asset_value=100_000, exposure_factor=0.5,
                                    annual_rate_occurrence=1.0)
        updated = engine.update_rates(sc["id"], "org1", asset_value=200_000)
        assert updated["single_loss_expectancy"] == pytest.approx(100_000.0)
        assert updated["annual_loss_expectancy"] == pytest.approx(100_000.0)

    def test_update_exposure_factor_recomputes(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "ransomware",
                                    asset_value=100_000, exposure_factor=0.5,
                                    annual_rate_occurrence=1.0)
        updated = engine.update_rates(sc["id"], "org1", exposure_factor=0.8)
        assert updated["single_loss_expectancy"] == pytest.approx(80_000.0)

    def test_update_aro_recomputes_ale(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "insider",
                                    asset_value=100_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        updated = engine.update_rates(sc["id"], "org1", annual_rate_occurrence=3.0)
        assert updated["annual_loss_expectancy"] == pytest.approx(300_000.0)

    def test_update_exposure_factor_clamped(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "ddos",
                                    asset_value=100_000, exposure_factor=0.5,
                                    annual_rate_occurrence=1.0)
        updated = engine.update_rates(sc["id"], "org1", exposure_factor=5.0)
        assert updated["exposure_factor"] == 1.0

    def test_update_unknown_scenario_returns_none(self, engine):
        result = engine.update_rates("nonexistent", "org1", asset_value=100_000)
        assert result is None

    def test_update_wrong_org_returns_none(self, engine):
        sc = engine.create_scenario("org_a", "SC", "Asset", "Actor", "malware",
                                    asset_value=100_000, exposure_factor=0.5,
                                    annual_rate_occurrence=1.0)
        result = engine.update_rates(sc["id"], "org_b", asset_value=200_000)
        assert result is None


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

class TestSnapshot:
    def test_snapshot_total_ale(self, engine):
        engine.create_scenario("org1", "S1", "A", "T", "malware",
                               asset_value=1_000_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        engine.create_scenario("org1", "S2", "B", "T", "ransomware",
                               asset_value=500_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        snap = engine.take_snapshot("org1")
        assert snap["total_ale"] == pytest.approx(1_500_000.0)

    def test_snapshot_avg_ale(self, engine):
        engine.create_scenario("org1", "S1", "A", "T", "malware",
                               asset_value=200_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        engine.create_scenario("org1", "S2", "B", "T", "insider",
                               asset_value=400_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        snap = engine.take_snapshot("org1")
        assert snap["avg_ale"] == pytest.approx(300_000.0)

    def test_snapshot_critical_count(self, engine):
        engine.create_scenario("org1", "Crit", "A", "T", "ransomware",
                               asset_value=2_000_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        engine.create_scenario("org1", "Low", "B", "T", "physical",
                               asset_value=1_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        snap = engine.take_snapshot("org1")
        assert snap["critical_scenarios"] == 1

    def test_snapshot_by_threat_type_dict(self, engine):
        engine.create_scenario("org1", "S1", "A", "T", "malware",
                               asset_value=100_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        engine.create_scenario("org1", "S2", "B", "T", "malware",
                               asset_value=200_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        snap = engine.take_snapshot("org1")
        assert isinstance(snap["by_threat_type"], dict)
        assert snap["by_threat_type"]["malware"] == pytest.approx(300_000.0)

    def test_snapshot_has_id_and_date(self, engine):
        snap = engine.take_snapshot("org1")
        assert snap["id"]
        assert snap["snapshot_date"]


# ---------------------------------------------------------------------------
# Portfolio summary
# ---------------------------------------------------------------------------

class TestPortfolioSummary:
    def test_summary_total_scenarios(self, engine):
        engine.create_scenario("org1", "S1", "A", "T", "malware",
                               asset_value=100_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        engine.create_scenario("org1", "S2", "B", "T", "insider",
                               asset_value=200_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        summary = engine.get_portfolio_summary("org1")
        assert summary["total_scenarios"] == 2

    def test_summary_by_risk_level(self, engine):
        engine.create_scenario("org1", "Crit", "A", "T", "ransomware",
                               asset_value=2_000_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        engine.create_scenario("org1", "Low", "B", "T", "physical",
                               asset_value=100, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        summary = engine.get_portfolio_summary("org1")
        assert "critical" in summary["by_risk_level"]
        assert summary["by_risk_level"]["critical"] >= 1

    def test_summary_top5(self, engine):
        for i in range(7):
            engine.create_scenario("org1", f"S{i}", "A", "T", "malware",
                                   asset_value=float((i + 1) * 10_000),
                                   exposure_factor=1.0, annual_rate_occurrence=1.0)
        summary = engine.get_portfolio_summary("org1")
        assert len(summary["top_5_ale_scenarios"]) == 5

    def test_summary_org_isolation(self, engine):
        engine.create_scenario("org_a", "S1", "A", "T", "ddos",
                               asset_value=100_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        engine.create_scenario("org_b", "S2", "B", "T", "ddos",
                               asset_value=200_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        summary_a = engine.get_portfolio_summary("org_a")
        assert summary_a["total_scenarios"] == 1
        summary_b = engine.get_portfolio_summary("org_b")
        assert summary_b["total_scenarios"] == 1


# ---------------------------------------------------------------------------
# Scenario detail
# ---------------------------------------------------------------------------

class TestScenarioDetail:
    def test_detail_includes_controls(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "malware",
                                    asset_value=1_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        engine.add_control(sc["id"], "org1", "Ctrl", "preventive",
                           implementation_cost=10_000, annual_cost=1_000, effectiveness_pct=40.0)
        detail = engine.get_scenario_detail(sc["id"], "org1")
        assert len(detail["controls"]) == 1

    def test_detail_recommended_controls_filtered(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "ransomware",
                                    asset_value=1_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        engine.add_control(sc["id"], "org1", "GoodCtrl", "preventive",
                           implementation_cost=10_000, annual_cost=1_000, effectiveness_pct=50.0)
        engine.add_control(sc["id"], "org1", "BadCtrl", "corrective",
                           implementation_cost=10_000_000, annual_cost=1_000_000, effectiveness_pct=1.0)
        detail = engine.get_scenario_detail(sc["id"], "org1")
        rec = detail["recommended_controls"]
        assert all(c["recommended"] == 1 for c in rec)

    def test_detail_not_found_returns_none(self, engine):
        assert engine.get_scenario_detail("nonexistent", "org1") is None

    def test_detail_org_isolation(self, engine):
        sc = engine.create_scenario("org_a", "SC", "Asset", "Actor", "malware",
                                    asset_value=100_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        assert engine.get_scenario_detail(sc["id"], "org_b") is None


# ---------------------------------------------------------------------------
# Snapshot history
# ---------------------------------------------------------------------------

class TestSnapshotHistory:
    def test_history_returns_list(self, engine):
        engine.take_snapshot("org1")
        engine.take_snapshot("org1")
        history = engine.get_snapshot_history("org1")
        assert len(history) >= 1

    def test_history_by_threat_type_deserialized(self, engine):
        engine.create_scenario("org1", "S", "A", "T", "ddos",
                               asset_value=100_000, exposure_factor=1.0,
                               annual_rate_occurrence=1.0)
        engine.take_snapshot("org1")
        history = engine.get_snapshot_history("org1")
        assert isinstance(history[0]["by_threat_type"], dict)

    def test_history_org_isolation(self, engine):
        engine.take_snapshot("org_a")
        history = engine.get_snapshot_history("org_b")
        assert history == []


# ---------------------------------------------------------------------------
# ROI analysis
# ---------------------------------------------------------------------------

class TestROIAnalysis:
    def test_roi_analysis_returns_positive_roi_only(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "malware",
                                    asset_value=1_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        engine.add_control(sc["id"], "org1", "GoodCtrl", "preventive",
                           implementation_cost=10_000, annual_cost=1_000, effectiveness_pct=50.0)
        engine.add_control(sc["id"], "org1", "BadCtrl", "corrective",
                           implementation_cost=10_000_000, annual_cost=5_000_000, effectiveness_pct=1.0)
        roi = engine.get_roi_analysis("org1")
        assert all(c["roi"] > 0 for c in roi)

    def test_roi_analysis_ordered_desc(self, engine):
        sc = engine.create_scenario("org1", "SC", "Asset", "Actor", "ransomware",
                                    asset_value=1_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        engine.add_control(sc["id"], "org1", "Best", "preventive",
                           implementation_cost=1_000, annual_cost=100, effectiveness_pct=80.0)
        engine.add_control(sc["id"], "org1", "Good", "detective",
                           implementation_cost=10_000, annual_cost=1_000, effectiveness_pct=40.0)
        roi = engine.get_roi_analysis("org1")
        if len(roi) >= 2:
            assert roi[0]["roi"] >= roi[1]["roi"]

    def test_roi_analysis_org_isolation(self, engine):
        sc = engine.create_scenario("org_a", "SC", "Asset", "Actor", "malware",
                                    asset_value=1_000_000, exposure_factor=1.0,
                                    annual_rate_occurrence=1.0)
        engine.add_control(sc["id"], "org_a", "Ctrl", "preventive",
                           implementation_cost=10_000, annual_cost=1_000, effectiveness_pct=50.0)
        roi = engine.get_roi_analysis("org_b")
        assert roi == []
