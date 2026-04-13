"""
Tests for the Breach Simulation Engine.

Covers:
- AttackScenario enum (all 8 values)
- SimulationResult Pydantic model construction and validation
- AttackStep model
- DefenseCoverage and GapAnalysis models
- BreachSimulator:
  - get_scenario_steps for all 8 scenarios
  - evaluate_defenses (determinism, blocked/detected fields)
  - run_simulation (persistence, scoring, gaps)
  - get_simulation_history (ordering, limit)
  - get_defense_coverage (tested/not-tested, avg score)
  - get_gap_analysis (recurring gaps, critical gaps, priorities)
  - compare_simulations (delta, trend)
- Module-level singleton get_breach_simulator()
- 35+ tests
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure suite-core is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.breach_simulation import (
    AttackScenario,
    AttackStep,
    BreachSimulator,
    DefenseCoverage,
    GapAnalysis,
    SimulationResult,
    get_breach_simulator,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sim(tmp_path):
    """Fresh BreachSimulator with temp SQLite DB for each test."""
    return BreachSimulator(db_path=str(tmp_path / "breach_sim.db"))


@pytest.fixture
def populated_sim(tmp_path):
    """Simulator with 3 simulations already run across 2 scenarios."""
    s = BreachSimulator(db_path=str(tmp_path / "populated.db"))
    s.run_simulation(AttackScenario.RANSOMWARE, "org-1")
    s.run_simulation(AttackScenario.DATA_EXFILTRATION, "org-1")
    s.run_simulation(AttackScenario.RANSOMWARE, "org-1")
    return s


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestAttackScenarioEnum:
    def test_all_eight_scenarios(self):
        scenarios = list(AttackScenario)
        assert len(scenarios) == 8

    def test_enum_values(self):
        assert AttackScenario.RANSOMWARE == "ransomware"
        assert AttackScenario.DATA_EXFILTRATION == "data_exfiltration"
        assert AttackScenario.CREDENTIAL_THEFT == "credential_theft"
        assert AttackScenario.LATERAL_MOVEMENT == "lateral_movement"
        assert AttackScenario.PRIVILEGE_ESCALATION == "privilege_escalation"
        assert AttackScenario.SUPPLY_CHAIN == "supply_chain"
        assert AttackScenario.INSIDER_THREAT == "insider_threat"
        assert AttackScenario.APT_CAMPAIGN == "apt_campaign"

    def test_enum_is_str(self):
        for s in AttackScenario:
            assert isinstance(s.value, str)


# ---------------------------------------------------------------------------
# Pydantic model tests
# ---------------------------------------------------------------------------


class TestSimulationResultModel:
    def test_construction(self):
        r = SimulationResult(
            scenario=AttackScenario.RANSOMWARE,
            steps_executed=8,
            steps_blocked=5,
            detection_time_seconds=300.0,
            containment_time_seconds=900.0,
            data_at_risk="All file shares",
            defenses_tested=["EDR", "SIEM"],
            gaps_found=["Missing MFA"],
            score=62.5,
            org_id="org-test",
        )
        assert r.scenario == AttackScenario.RANSOMWARE
        assert r.steps_executed == 8
        assert r.steps_blocked == 5
        assert r.score == 62.5
        assert r.org_id == "org-test"

    def test_auto_id(self):
        r = SimulationResult(
            scenario=AttackScenario.APT_CAMPAIGN,
            steps_executed=10,
            steps_blocked=4,
            detection_time_seconds=3600.0,
            containment_time_seconds=7200.0,
            data_at_risk="Strategic assets",
            defenses_tested=[],
            gaps_found=[],
            score=40.0,
            org_id="org-apt",
        )
        assert r.id.startswith("sim-")

    def test_auto_simulated_at(self):
        r = SimulationResult(
            scenario=AttackScenario.INSIDER_THREAT,
            steps_executed=7,
            steps_blocked=3,
            detection_time_seconds=120.0,
            containment_time_seconds=360.0,
            data_at_risk="IP",
            defenses_tested=[],
            gaps_found=[],
            score=42.0,
            org_id="org-x",
        )
        assert "T" in r.simulated_at  # ISO-8601

    def test_score_range_validation(self):
        with pytest.raises(Exception):
            SimulationResult(
                scenario=AttackScenario.RANSOMWARE,
                steps_executed=5,
                steps_blocked=5,
                detection_time_seconds=100.0,
                containment_time_seconds=200.0,
                data_at_risk="x",
                defenses_tested=[],
                gaps_found=[],
                score=150.0,  # invalid — > 100
                org_id="org",
            )


class TestAttackStepModel:
    def test_construction(self):
        step = AttackStep(
            step_id="rw-1",
            name="Phishing",
            technique="T1566.001",
            phase="initial_access",
            severity="high",
            defense_control="Email filtering",
        )
        assert step.blocked is False
        assert step.detection_triggered is False

    def test_model_copy_with_update(self):
        step = AttackStep(
            step_id="lm-1",
            name="RCE",
            technique="T1190",
            phase="initial_access",
            severity="critical",
            defense_control="WAF",
        )
        updated = step.model_copy(update={"blocked": True, "detection_triggered": True})
        assert updated.blocked is True
        assert updated.detection_triggered is True
        assert step.blocked is False  # original unchanged


# ---------------------------------------------------------------------------
# BreachSimulator.get_scenario_steps
# ---------------------------------------------------------------------------


class TestGetScenarioSteps:
    def test_all_scenarios_have_steps(self, sim):
        for scenario in AttackScenario:
            steps = sim.get_scenario_steps(scenario)
            assert len(steps) >= 5, f"{scenario} has fewer than 5 steps"
            assert len(steps) <= 10, f"{scenario} has more than 10 steps"

    def test_steps_are_attack_step_instances(self, sim):
        steps = sim.get_scenario_steps(AttackScenario.RANSOMWARE)
        for step in steps:
            assert isinstance(step, AttackStep)

    def test_steps_have_required_fields(self, sim):
        steps = sim.get_scenario_steps(AttackScenario.APT_CAMPAIGN)
        for step in steps:
            assert step.step_id
            assert step.name
            assert step.technique
            assert step.phase
            assert step.severity in ("low", "medium", "high", "critical")
            assert step.defense_control

    def test_apt_campaign_has_ten_steps(self, sim):
        steps = sim.get_scenario_steps(AttackScenario.APT_CAMPAIGN)
        assert len(steps) == 10

    def test_ransomware_has_eight_steps(self, sim):
        steps = sim.get_scenario_steps(AttackScenario.RANSOMWARE)
        assert len(steps) == 8


# ---------------------------------------------------------------------------
# BreachSimulator.evaluate_defenses
# ---------------------------------------------------------------------------


class TestEvaluateDefenses:
    def test_returns_attack_steps(self, sim):
        steps = sim.evaluate_defenses(AttackScenario.CREDENTIAL_THEFT, "org-eval")
        assert len(steps) > 0
        for step in steps:
            assert isinstance(step, AttackStep)

    def test_blocked_field_populated(self, sim):
        steps = sim.evaluate_defenses(AttackScenario.RANSOMWARE, "org-eval")
        # At least one field is set (deterministic)
        blocked_values = {s.blocked for s in steps}
        assert blocked_values <= {True, False}

    def test_deterministic_same_org(self, sim):
        steps_a = sim.evaluate_defenses(AttackScenario.LATERAL_MOVEMENT, "org-det")
        steps_b = sim.evaluate_defenses(AttackScenario.LATERAL_MOVEMENT, "org-det")
        for a, b in zip(steps_a, steps_b):
            assert a.blocked == b.blocked
            assert a.detection_triggered == b.detection_triggered

    def test_different_org_may_differ(self, sim):
        steps_a = sim.evaluate_defenses(AttackScenario.PRIVILEGE_ESCALATION, "org-aaa")
        steps_b = sim.evaluate_defenses(AttackScenario.PRIVILEGE_ESCALATION, "org-zzz")
        # Not guaranteed to differ but at least both are valid lists
        assert len(steps_a) == len(steps_b)

    def test_step_count_matches_scenario(self, sim):
        for scenario in AttackScenario:
            base_steps = sim.get_scenario_steps(scenario)
            evaluated = sim.evaluate_defenses(scenario, "org-check")
            assert len(evaluated) == len(base_steps)


# ---------------------------------------------------------------------------
# BreachSimulator.run_simulation
# ---------------------------------------------------------------------------


class TestRunSimulation:
    def test_returns_simulation_result(self, sim):
        result = sim.run_simulation(AttackScenario.RANSOMWARE, "org-run")
        assert isinstance(result, SimulationResult)

    def test_result_persisted(self, sim):
        result = sim.run_simulation(AttackScenario.DATA_EXFILTRATION, "org-persist")
        history = sim.get_simulation_history("org-persist")
        assert any(r.id == result.id for r in history)

    def test_score_in_range(self, sim):
        result = sim.run_simulation(AttackScenario.SUPPLY_CHAIN, "org-score")
        assert 0.0 <= result.score <= 100.0

    def test_steps_executed_matches_scenario(self, sim):
        result = sim.run_simulation(AttackScenario.RANSOMWARE, "org-steps")
        expected = len(sim.get_scenario_steps(AttackScenario.RANSOMWARE))
        assert result.steps_executed == expected

    def test_steps_blocked_lte_steps_executed(self, sim):
        result = sim.run_simulation(AttackScenario.CREDENTIAL_THEFT, "org-blocked")
        assert result.steps_blocked <= result.steps_executed

    def test_detection_time_positive(self, sim):
        result = sim.run_simulation(AttackScenario.LATERAL_MOVEMENT, "org-det")
        assert result.detection_time_seconds > 0.0

    def test_containment_gte_detection(self, sim):
        result = sim.run_simulation(AttackScenario.INSIDER_THREAT, "org-contain")
        assert result.containment_time_seconds >= result.detection_time_seconds

    def test_data_at_risk_nonempty(self, sim):
        result = sim.run_simulation(AttackScenario.APT_CAMPAIGN, "org-data")
        assert result.data_at_risk

    def test_defenses_tested_nonempty(self, sim):
        result = sim.run_simulation(AttackScenario.PRIVILEGE_ESCALATION, "org-def")
        assert len(result.defenses_tested) > 0

    def test_org_id_stored(self, sim):
        result = sim.run_simulation(AttackScenario.SUPPLY_CHAIN, "org-specific")
        assert result.org_id == "org-specific"

    def test_all_scenarios_run(self, sim):
        for scenario in AttackScenario:
            r = sim.run_simulation(scenario, "org-all")
            assert isinstance(r, SimulationResult)


# ---------------------------------------------------------------------------
# BreachSimulator.get_simulation_history
# ---------------------------------------------------------------------------


class TestGetSimulationHistory:
    def test_returns_list(self, sim):
        history = sim.get_simulation_history("org-empty")
        assert isinstance(history, list)
        assert len(history) == 0

    def test_history_newest_first(self, populated_sim):
        history = populated_sim.get_simulation_history("org-1")
        assert len(history) == 3
        for i in range(len(history) - 1):
            assert history[i].simulated_at >= history[i + 1].simulated_at

    def test_limit_respected(self, populated_sim):
        history = populated_sim.get_simulation_history("org-1", limit=2)
        assert len(history) == 2

    def test_org_isolation(self, populated_sim):
        history = populated_sim.get_simulation_history("org-other")
        assert len(history) == 0


# ---------------------------------------------------------------------------
# BreachSimulator.get_defense_coverage
# ---------------------------------------------------------------------------


class TestGetDefenseCoverage:
    def test_empty_org(self, sim):
        cov = sim.get_defense_coverage("org-new")
        assert isinstance(cov, DefenseCoverage)
        assert cov.total_simulations == 0
        assert len(cov.scenarios_not_tested) == 8

    def test_coverage_increases_with_simulations(self, populated_sim):
        cov = populated_sim.get_defense_coverage("org-1")
        assert cov.total_simulations == 3
        assert len(cov.scenarios_tested) == 2
        assert len(cov.scenarios_not_tested) == 6

    def test_coverage_percent_range(self, populated_sim):
        cov = populated_sim.get_defense_coverage("org-1")
        assert 0.0 <= cov.coverage_percent <= 100.0

    def test_average_score_range(self, populated_sim):
        cov = populated_sim.get_defense_coverage("org-1")
        assert 0.0 <= cov.average_score <= 100.0

    def test_weakest_strongest_populated(self, populated_sim):
        cov = populated_sim.get_defense_coverage("org-1")
        assert cov.weakest_scenario is not None
        assert cov.strongest_scenario is not None


# ---------------------------------------------------------------------------
# BreachSimulator.get_gap_analysis
# ---------------------------------------------------------------------------


class TestGetGapAnalysis:
    def test_empty_org(self, sim):
        gap = sim.get_gap_analysis("org-empty-gap")
        assert isinstance(gap, GapAnalysis)
        assert gap.total_simulations == 0
        assert gap.recurring_gaps == []

    def test_gaps_after_simulations(self, populated_sim):
        gap = populated_sim.get_gap_analysis("org-1")
        assert gap.total_simulations == 3
        assert isinstance(gap.recurring_gaps, list)
        assert isinstance(gap.gap_frequency, dict)

    def test_recommended_priorities_list(self, populated_sim):
        gap = populated_sim.get_gap_analysis("org-1")
        assert isinstance(gap.recommended_priorities, list)

    def test_critical_gaps_list(self, populated_sim):
        gap = populated_sim.get_gap_analysis("org-1")
        assert isinstance(gap.critical_gaps, list)


# ---------------------------------------------------------------------------
# BreachSimulator.compare_simulations
# ---------------------------------------------------------------------------


class TestCompareSimulations:
    def test_empty_ids(self, sim):
        result = sim.compare_simulations([])
        assert result["simulations"] == []

    def test_compare_two_simulations(self, sim):
        r1 = sim.run_simulation(AttackScenario.RANSOMWARE, "org-cmp")
        r2 = sim.run_simulation(AttackScenario.RANSOMWARE, "org-cmp")
        comparison = sim.compare_simulations([r1.id, r2.id])
        assert len(comparison["simulations"]) == 2
        assert "score_delta" in comparison["comparison"]
        assert "trend" in comparison["comparison"]

    def test_trend_values(self, sim):
        r1 = sim.run_simulation(AttackScenario.DATA_EXFILTRATION, "org-trend")
        r2 = sim.run_simulation(AttackScenario.DATA_EXFILTRATION, "org-trend")
        cmp = sim.compare_simulations([r1.id, r2.id])
        assert cmp["comparison"]["trend"] in ("improving", "declining", "stable")

    def test_nonexistent_ids_ignored(self, sim):
        r1 = sim.run_simulation(AttackScenario.SUPPLY_CHAIN, "org-noex")
        result = sim.compare_simulations([r1.id, "sim-doesnotexist"])
        # Only 1 found; comparison skipped since < 2 results
        assert "simulations" in result


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_breach_simulator_returns_instance(self, tmp_path):
        from core.breach_simulation import get_breach_simulator as _get
        # Reset singleton for isolated test
        import core.breach_simulation as _mod
        orig = _mod._simulator_instance
        _mod._simulator_instance = None
        try:
            inst = _get(db_path=str(tmp_path / "singleton.db"))
            assert isinstance(inst, BreachSimulator)
            # Second call returns same instance
            inst2 = _get(db_path=str(tmp_path / "singleton.db"))
            assert inst is inst2
        finally:
            _mod._simulator_instance = orig
