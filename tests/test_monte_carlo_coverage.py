"""Tests for core.monte_carlo — FAIR Monte Carlo risk engine."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.monte_carlo import (
    FAIRInputs,
    MonteCarloResult,
    MonteCarloRiskEngine,
    RiskCategory,
    ThreatCapability,
)


# ── Enums ────────────────────────────────────────────────────────────

class TestRiskCategory:
    def test_values(self):
        assert RiskCategory.CONFIDENTIALITY.value == "confidentiality"
        assert RiskCategory.INTEGRITY.value == "integrity"
        assert RiskCategory.AVAILABILITY.value == "availability"
        assert RiskCategory.FRAUD.value == "fraud"
        assert RiskCategory.REPUTATION.value == "reputation"
        assert RiskCategory.REGULATORY.value == "regulatory"

    def test_all_members(self):
        assert len(RiskCategory) == 6


class TestThreatCapability:
    def test_values(self):
        assert ThreatCapability.SCRIPT_KIDDIE.value == "script_kiddie"
        assert ThreatCapability.OPPORTUNIST.value == "opportunist"
        assert ThreatCapability.ORGANIZED_CRIME.value == "organized_crime"
        assert ThreatCapability.NATION_STATE.value == "nation_state"
        assert ThreatCapability.INSIDER.value == "insider"

    def test_all_members(self):
        assert len(ThreatCapability) == 5


# ── FAIRInputs ───────────────────────────────────────────────────────

class TestFAIRInputs:
    def test_defaults(self):
        inputs = FAIRInputs()
        assert inputs.tef_min == 0.1
        assert inputs.tef_max == 10.0
        assert inputs.tef_mode == 2.0
        assert inputs.vuln_min == 0.1
        assert inputs.vuln_max == 0.9
        assert inputs.vuln_mode == 0.5
        assert inputs.primary_loss_min == 10000
        assert inputs.primary_loss_max == 1000000
        assert inputs.slef_probability == 0.3
        assert inputs.asset_value == 1000000

    def test_custom_inputs(self):
        inputs = FAIRInputs(
            tef_min=1.0,
            tef_max=50.0,
            tef_mode=10.0,
            vuln_min=0.5,
            vuln_max=0.95,
            vuln_mode=0.8,
        )
        assert inputs.tef_min == 1.0
        assert inputs.tef_max == 50.0
        assert inputs.vuln_mode == 0.8


# ── MonteCarloResult ────────────────────────────────────────────────

class TestMonteCarloResult:
    def test_to_dict(self):
        result = MonteCarloResult(
            mean_annual_loss=150000.0,
            median_annual_loss=120000.0,
            std_annual_loss=80000.0,
            var_90=250000.0,
            var_95=350000.0,
            var_99=500000.0,
            prob_exceed_100k=0.65,
            prob_exceed_500k=0.12,
            prob_exceed_1m=0.03,
            prob_exceed_5m=0.001,
            breach_probability=0.72,
            breach_probability_ci_lower=0.68,
            breach_probability_ci_upper=0.76,
            percentiles={50: 120000.0, 95: 350000.0},
            iterations=10000,
            execution_time_ms=42.5,
        )
        d = result.to_dict()
        assert d["mean_annual_loss"] == 150000.0
        assert d["value_at_risk"]["var_95"] == 350000.0
        assert d["loss_exceedance"]["prob_exceed_1m"] == 0.03
        assert d["breach_probability"]["estimate"] == 0.72
        assert d["iterations"] == 10000
        assert "50" in d["percentiles"]


# ── MonteCarloRiskEngine ────────────────────────────────────────────

class TestMonteCarloRiskEngine:
    def test_init_defaults(self):
        engine = MonteCarloRiskEngine()
        assert engine.iterations == 10000

    def test_init_custom(self):
        engine = MonteCarloRiskEngine(iterations=500, seed=42)
        assert engine.iterations == 500

    def test_simulate_basic(self):
        engine = MonteCarloRiskEngine(iterations=1000, seed=42)
        inputs = FAIRInputs()
        result = engine.simulate(inputs)
        assert isinstance(result, MonteCarloResult)
        assert result.mean_annual_loss >= 0
        assert result.median_annual_loss >= 0
        assert result.std_annual_loss >= 0
        assert result.var_90 >= 0
        assert result.var_95 >= result.var_90
        assert result.var_99 >= result.var_95
        assert 0 <= result.breach_probability <= 1
        assert result.breach_probability_ci_lower <= result.breach_probability
        assert result.breach_probability_ci_upper >= result.breach_probability
        assert result.iterations == 1000
        assert result.execution_time_ms > 0

    def test_simulate_with_distribution(self):
        engine = MonteCarloRiskEngine(iterations=500, seed=99)
        result = engine.simulate(FAIRInputs(), include_distribution=True)
        assert len(result.loss_distribution) == 500

    def test_simulate_without_distribution(self):
        engine = MonteCarloRiskEngine(iterations=500, seed=99)
        result = engine.simulate(FAIRInputs(), include_distribution=False)
        assert len(result.loss_distribution) == 0

    def test_simulate_percentiles(self):
        engine = MonteCarloRiskEngine(iterations=1000, seed=42)
        result = engine.simulate(FAIRInputs())
        assert 5 in result.percentiles
        assert 50 in result.percentiles
        assert 95 in result.percentiles
        assert 99 in result.percentiles
        assert result.percentiles[5] <= result.percentiles[50]
        assert result.percentiles[50] <= result.percentiles[95]

    def test_simulate_high_risk(self):
        engine = MonteCarloRiskEngine(iterations=1000, seed=42)
        inputs = FAIRInputs(
            tef_min=5.0,
            tef_max=50.0,
            tef_mode=20.0,
            vuln_min=0.7,
            vuln_max=0.99,
            vuln_mode=0.9,
            primary_loss_min=100000,
            primary_loss_max=10000000,
            primary_loss_mode=1000000,
        )
        result = engine.simulate(inputs)
        assert result.breach_probability > 0.5
        assert result.mean_annual_loss > 100000

    def test_simulate_low_risk(self):
        engine = MonteCarloRiskEngine(iterations=1000, seed=42)
        inputs = FAIRInputs(
            tef_min=0.01,
            tef_max=0.1,
            tef_mode=0.05,
            vuln_min=0.01,
            vuln_max=0.1,
            vuln_mode=0.05,
        )
        result = engine.simulate(inputs)
        assert result.breach_probability < 0.5

    def test_sample_pert_degenerate(self):
        engine = MonteCarloRiskEngine(iterations=100, seed=42)
        result = engine._sample_pert(5.0, 5.0, 5.0, size=10)
        assert all(v == 5.0 for v in result)

    def test_sample_lognormal_zero_mean(self):
        engine = MonteCarloRiskEngine(iterations=100, seed=42)
        result = engine._sample_lognormal(0.0, 1.0, size=10)
        assert all(v == 0.0 for v in result)

    def test_simulate_from_cvss_critical(self):
        engine = MonteCarloRiskEngine(iterations=1000, seed=42)
        result = engine.simulate_from_cvss(
            cvss_score=9.8,
            asset_value=5000000,
            has_exploit=True,
            is_internet_facing=True,
        )
        assert isinstance(result, MonteCarloResult)
        assert result.breach_probability > 0.5

    def test_simulate_from_cvss_low(self):
        engine = MonteCarloRiskEngine(iterations=1000, seed=42)
        result = engine.simulate_from_cvss(
            cvss_score=2.0,
            asset_value=100000,
            has_exploit=False,
            is_internet_facing=False,
        )
        assert isinstance(result, MonteCarloResult)

    def test_simulate_from_cvss_with_exploit(self):
        engine = MonteCarloRiskEngine(iterations=500, seed=42)
        r_without = engine.simulate_from_cvss(cvss_score=7.5, has_exploit=False)
        engine2 = MonteCarloRiskEngine(iterations=500, seed=42)
        r_with = engine2.simulate_from_cvss(cvss_score=7.5, has_exploit=True)
        # With exploit should generally have higher breach probability
        assert isinstance(r_with, MonteCarloResult)
        assert isinstance(r_without, MonteCarloResult)

    def test_simulate_from_cvss_internet_facing(self):
        engine = MonteCarloRiskEngine(iterations=500, seed=42)
        result = engine.simulate_from_cvss(
            cvss_score=7.0, is_internet_facing=True
        )
        assert result.breach_probability > 0

    def test_simulate_from_cvss_different_industries(self):
        for industry in ["technology", "healthcare", "financial", "retail"]:
            engine = MonteCarloRiskEngine(iterations=200, seed=42)
            result = engine.simulate_from_cvss(cvss_score=7.5, industry=industry)
            assert isinstance(result, MonteCarloResult)

    def test_reproducibility_with_seed(self):
        inputs = FAIRInputs()
        e1 = MonteCarloRiskEngine(iterations=500, seed=12345)
        r1 = e1.simulate(inputs)
        e2 = MonteCarloRiskEngine(iterations=500, seed=12345)
        r2 = e2.simulate(inputs)
        assert r1.mean_annual_loss == r2.mean_annual_loss
        assert r1.breach_probability == r2.breach_probability

    def test_loss_exceedance_probabilities(self):
        engine = MonteCarloRiskEngine(iterations=1000, seed=42)
        result = engine.simulate(FAIRInputs())
        # Higher thresholds should have lower exceedance probability
        assert result.prob_exceed_100k >= result.prob_exceed_500k
        assert result.prob_exceed_500k >= result.prob_exceed_1m
        assert result.prob_exceed_1m >= result.prob_exceed_5m

    def test_confidence_interval_bounds(self):
        engine = MonteCarloRiskEngine(iterations=1000, seed=42)
        result = engine.simulate(FAIRInputs())
        assert 0 <= result.breach_probability_ci_lower <= 1
        assert 0 <= result.breach_probability_ci_upper <= 1
        assert result.breach_probability_ci_lower <= result.breach_probability_ci_upper
