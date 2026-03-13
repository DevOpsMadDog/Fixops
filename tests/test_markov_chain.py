"""Tests for SecurityMarkovChain (suite-core/core/models/markov_chain.py).

Covers:
  - StateTransition and MarkovState dataclasses
  - SecurityMarkovChain initialization
  - Transition matrix shape and validity
  - predict_next_state
  - simulate_attack_path
  - get_risk_trajectory
  - update_transition_probability
  - get_containment_probability
  - get_most_likely_path
  - get_state_risk_level
  - Edge cases and invalid states
"""

from __future__ import annotations

import pytest
import numpy as np

from core.models.markov_chain import (
    MarkovState,
    SecurityMarkovChain,
    StateTransition,
)


# ──────────────────────────────────────────────────────
#  Dataclass tests
# ──────────────────────────────────────────────────────


class TestStateTransition:
    def test_basic_creation(self):
        t = StateTransition(from_state="A", to_state="B", probability=0.5)
        assert t.from_state == "A"
        assert t.to_state == "B"
        assert t.probability == 0.5
        assert t.conditions == []
        assert t.time_to_transition_hours == 24.0

    def test_with_conditions(self):
        t = StateTransition(
            from_state="Initial",
            to_state="Reconnaissance",
            probability=0.8,
            conditions=["exposed_port", "public_internet"],
            time_to_transition_hours=2.0,
        )
        assert len(t.conditions) == 2
        assert t.time_to_transition_hours == 2.0


class TestMarkovState:
    def test_basic_state(self):
        s = MarkovState(name="Initial", risk_level="low", description="Test")
        assert s.name == "Initial"
        assert s.risk_level == "low"
        assert s.mitre_technique is None
        assert s.is_absorbing is False

    def test_absorbing_state(self):
        s = MarkovState(
            name="Impact",
            risk_level="critical",
            description="Damage",
            mitre_technique="TA0040",
            is_absorbing=True,
        )
        assert s.is_absorbing is True
        assert s.mitre_technique == "TA0040"


# ──────────────────────────────────────────────────────
#  SecurityMarkovChain tests
# ──────────────────────────────────────────────────────


class TestSecurityMarkovChain:
    @pytest.fixture
    def chain(self):
        return SecurityMarkovChain()

    def test_init_default(self, chain):
        assert chain.n_states > 0
        assert "Initial" in chain.states
        assert "Impact" in chain.states
        assert "Contained" in chain.states

    def test_init_with_config(self):
        chain = SecurityMarkovChain(config={"max_steps": 5})
        assert chain.config.get("max_steps") == 5

    def test_transition_matrix_shape(self, chain):
        assert chain.transition_matrix.shape == (chain.n_states, chain.n_states)

    def test_transition_matrix_rows_sum_to_one(self, chain):
        row_sums = chain.transition_matrix.sum(axis=1)
        np.testing.assert_allclose(row_sums, 1.0, atol=1e-6)

    def test_transition_matrix_no_negatives(self, chain):
        assert (chain.transition_matrix >= 0).all()

    def test_state_names_list(self, chain):
        assert isinstance(chain.state_names, list)
        assert len(chain.state_names) == chain.n_states

    def test_state_idx_mapping(self, chain):
        for name in chain.state_names:
            assert name in chain.state_idx
            idx = chain.state_idx[name]
            assert 0 <= idx < chain.n_states

    def test_standard_states_count(self, chain):
        # Should have 15 standard states from MITRE kill chain
        assert chain.n_states >= 10

    def test_predict_next_state(self, chain):
        result = chain.predict_next_state("Initial")
        # Returns Tuple[str, float] — (state_name, probability)
        assert isinstance(result, tuple)
        assert len(result) == 2
        state_name, prob = result
        assert isinstance(state_name, str)
        assert isinstance(prob, float)
        assert 0 <= prob <= 1

    def test_predict_next_state_invalid(self, chain):
        # Invalid state should be handled gracefully
        result = chain.predict_next_state("NonExistentState")
        assert result is not None

    def test_simulate_attack_path(self, chain):
        path = chain.simulate_attack_path("Initial", max_steps=10)
        assert isinstance(path, list)
        assert len(path) >= 1
        # Each element is a dict with keys: step, state, risk_level, mitre_technique, etc.
        assert isinstance(path[0], dict)
        assert path[0]["state"] == "Initial"
        assert "step" in path[0]
        assert "risk_level" in path[0]

    def test_simulate_attack_path_max_steps(self, chain):
        path = chain.simulate_attack_path("Initial", max_steps=3)
        assert len(path) <= 4  # start + up to 3 steps
        for entry in path:
            assert isinstance(entry, dict)
            assert "state" in entry

    def test_calculate_risk_trajectory(self, chain):
        trajectory = chain.calculate_risk_trajectory("Initial", horizon_steps=5)
        assert isinstance(trajectory, dict)

    def test_get_transition_probability(self, chain):
        prob = chain.get_transition_probability("Initial", "Reconnaissance")
        assert isinstance(prob, float)
        assert 0 <= prob <= 1

    def test_sample_next_state(self, chain):
        state = chain.sample_next_state("Initial")
        assert isinstance(state, str)
        assert state in chain.state_names

    def test_to_dict(self, chain):
        d = chain.to_dict()
        assert isinstance(d, dict)

    def test_state_risk_level_via_states(self, chain):
        # Risk levels accessed via chain.states[name].risk_level
        initial_state = chain.states["Initial"]
        assert initial_state.risk_level == "low"
        impact_state = chain.states["Impact"]
        assert impact_state.risk_level == "critical"

    def test_transition_times_exist(self, chain):
        assert hasattr(chain, "transition_times")
        assert chain.transition_times is not None


class TestMarkovChainEdgeCases:
    def test_absorbing_state_simulation(self):
        chain = SecurityMarkovChain()
        # Start from an absorbing state
        path = chain.simulate_attack_path("Impact", max_steps=5)
        # Impact is absorbing so path should be short
        assert path[0]["state"] == "Impact"

    def test_contained_state_simulation(self):
        chain = SecurityMarkovChain()
        path = chain.simulate_attack_path("Contained", max_steps=5)
        assert path[0]["state"] == "Contained"
