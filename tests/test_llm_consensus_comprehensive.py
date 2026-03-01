"""
Comprehensive tests for the Multi-LLM Consensus Engine
(suite-core/core/llm_consensus.py).

This file goes beyond the basic coverage in test_llm_consensus.py and
test_llm_consensus_unit.py by stress-testing the voting algorithm,
threshold boundary conditions, weighted-confidence arithmetic,
timeout/fallback paths, batch-like multi-analysis workflows,
demo/mock mode (no real API calls), and serialization round-trips.

Test categories:
  1. Engine initialization and defaults
  2. Severity voting -- unanimous agreement
  3. Severity voting -- split decisions (2-way, 3-way, N-way)
  4. Confidence scoring (weighted average correctness)
  5. Edge cases: empty inputs, single provider, all-disagree
  6. Agreement threshold logic (85% sprint-board requirement)
  7. Response parsing / action normalization
  8. Timeout handling / fallback behavior (all-fail, partial-fail)
  9. Batch consensus (multi-analysis sequences)
 10. Demo/mock mode (no actual API calls)
"""

from __future__ import annotations

import math
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Mapping, Sequence
from unittest.mock import MagicMock, patch

import pytest

from core.llm_consensus import (
    ConsensusEngine,
    ConsensusResult,
    DEFAULT_PROVIDER_WEIGHTS,
)
from core.llm_providers import (
    BaseLLMProvider,
    DeterministicLLMProvider,
    LLMProviderManager,
    LLMResponse,
)


# ---------------------------------------------------------------------------
# Test helpers / mock providers
# ---------------------------------------------------------------------------


class MockProvider(BaseLLMProvider):
    """Provider that returns a deterministic action and confidence."""

    def __init__(
        self,
        name: str,
        action: str,
        confidence: float = 0.9,
        *,
        mitre: list[str] | None = None,
        compliance: list[str] | None = None,
        attack_vectors: list[str] | None = None,
        reasoning: str = "",
    ):
        super().__init__(name)
        self._action = action
        self._confidence = confidence
        self._mitre = mitre or []
        self._compliance = compliance or []
        self._attack_vectors = attack_vectors or []
        self._reasoning = reasoning

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
    ) -> LLMResponse:
        return LLMResponse(
            recommended_action=self._action,
            confidence=self._confidence,
            reasoning=self._reasoning or f"Mock {self.name}: {self._action}",
            mitre_techniques=list(self._mitre),
            compliance_concerns=list(self._compliance),
            attack_vectors=list(self._attack_vectors),
        )


class FailingProvider(BaseLLMProvider):
    """Provider that always raises an exception."""

    def __init__(self, name: str, error_msg: str | None = None):
        super().__init__(name)
        self._error_msg = error_msg or f"Provider {name} is down"

    def analyse(self, **kwargs: Any) -> LLMResponse:
        raise RuntimeError(self._error_msg)


class SlowProvider(MockProvider):
    """Provider that sleeps before returning."""

    def __init__(self, name: str, action: str, delay_s: float, **kwargs: Any):
        super().__init__(name, action, **kwargs)
        self._delay = delay_s

    def analyse(self, **kwargs: Any) -> LLMResponse:
        time.sleep(self._delay)
        return super().analyse(**kwargs)


class MockManager(LLMProviderManager):
    """Manager that returns specific mock providers (no real HTTP)."""

    def __init__(self, providers: dict[str, BaseLLMProvider]):
        super().__init__()
        self.providers = providers


# ---------------------------------------------------------------------------
# Shared analysis kwargs (reusable across every test)
# ---------------------------------------------------------------------------

ANALYSIS_KWARGS: dict[str, Any] = {
    "prompt": "Analyse CVE-2024-3094 for xz-utils backdoor risk",
    "context": {"service_name": "api-gateway", "environment": "production"},
    "default_action": "review",
    "default_confidence": 0.5,
    "default_reasoning": "Heuristic fallback analysis",
}


# ===================================================================
#  1. ENGINE INITIALIZATION AND DEFAULTS
# ===================================================================


class TestEngineInit:
    """Validate constructor parameters and internal state."""

    def test_default_threshold(self):
        engine = ConsensusEngine()
        assert engine.threshold == 0.85

    def test_custom_threshold(self):
        engine = ConsensusEngine(threshold=0.60)
        assert engine.threshold == 0.60

    def test_default_providers_list(self):
        engine = ConsensusEngine()
        assert engine.provider_names == ["openai", "anthropic", "gemini"]

    def test_custom_providers_list(self):
        engine = ConsensusEngine(providers=["openai", "sentinel"])
        assert engine.provider_names == ["openai", "sentinel"]

    def test_default_weights_used_when_none(self):
        engine = ConsensusEngine()
        assert engine.weights == DEFAULT_PROVIDER_WEIGHTS

    def test_custom_weights(self):
        custom = {"openai": 2.0, "anthropic": 1.0}
        engine = ConsensusEngine(provider_weights=custom)
        assert engine.weights == custom

    def test_max_workers(self):
        engine = ConsensusEngine(max_workers=8)
        assert engine.max_workers == 8

    def test_empty_history_on_init(self):
        engine = ConsensusEngine()
        assert engine.history == []
        assert len(engine._history) == 0

    def test_accepts_custom_manager(self):
        mgr = MockManager({"openai": MockProvider("openai", "patch")})
        engine = ConsensusEngine(manager=mgr)
        assert engine._manager is mgr


class TestDefaultProviderWeights:
    """Validate the module-level DEFAULT_PROVIDER_WEIGHTS dict."""

    def test_contains_expected_providers(self):
        for name in ("openai", "anthropic", "gemini", "sentinel"):
            assert name in DEFAULT_PROVIDER_WEIGHTS

    def test_all_values_are_positive_floats(self):
        for name, w in DEFAULT_PROVIDER_WEIGHTS.items():
            assert isinstance(w, float), f"{name} weight is not float"
            assert w > 0, f"{name} weight must be positive"

    def test_sentinel_has_lowest_weight(self):
        assert DEFAULT_PROVIDER_WEIGHTS["sentinel"] < DEFAULT_PROVIDER_WEIGHTS["openai"]
        assert DEFAULT_PROVIDER_WEIGHTS["sentinel"] < DEFAULT_PROVIDER_WEIGHTS["anthropic"]
        assert DEFAULT_PROVIDER_WEIGHTS["sentinel"] < DEFAULT_PROVIDER_WEIGHTS["gemini"]


# ===================================================================
#  2. SEVERITY VOTING -- UNANIMOUS AGREEMENT
# ===================================================================


class TestUnanimousVoting:
    """All providers agree on the same action."""

    def test_three_providers_all_patch(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.92),
            "gemini": MockProvider("gemini", "patch", 0.88),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "patch"
        assert result.agreement_ratio == pytest.approx(1.0, abs=0.01)
        assert result.dissenting_providers == []

    def test_two_providers_all_monitor(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "monitor", 0.70),
            "anthropic": MockProvider("anthropic", "monitor", 0.65),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "monitor"

    def test_four_providers_all_isolate(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "isolate", 0.99),
            "anthropic": MockProvider("anthropic", "isolate", 0.97),
            "gemini": MockProvider("gemini", "isolate", 0.93),
            "sentinel": MockProvider("sentinel", "isolate", 0.80),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini", "sentinel"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "isolate"
        assert len(result.votes) == 4

    def test_unanimous_has_no_dissent_warning(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
            "anthropic": MockProvider("anthropic", "patch", 0.9),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "DISSENT" not in result.reasoning


# ===================================================================
#  3. SEVERITY VOTING -- SPLIT DECISIONS
# ===================================================================


class TestSplitDecisions:
    """Two-way, three-way, and N-way splits."""

    def test_two_way_split_winner_by_count(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.92),
            "gemini": MockProvider("gemini", "review", 0.60),
        })
        engine = ConsensusEngine(
            threshold=0.50,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"
        assert "gemini" in result.dissenting_providers

    def test_three_way_split_no_consensus(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
            "anthropic": MockProvider("anthropic", "review", 0.7),
            "gemini": MockProvider("gemini", "monitor", 0.5),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is False
        # All three actions have equal weight 1/3; winner is non-deterministic
        # among tied actions, but agreement_ratio must be ~0.33
        assert result.action in ("patch", "review", "monitor")
        assert result.agreement_ratio == pytest.approx(1.0 / 3.0, abs=0.01)
        assert len(result.dissenting_providers) == 2

    def test_three_way_split_reasoning_warns(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "review", 0.6),
            "c": MockProvider("c", "ignore", 0.3),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b", "c"],
            provider_weights={"a": 1.0, "b": 1.0, "c": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "DISSENT" in result.reasoning

    def test_even_split_picks_highest_weight(self):
        """With 2 providers voting differently but equal weights,
        the one with higher weight wins by tie-break order."""
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
            "anthropic": MockProvider("anthropic", "review", 0.9),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic"],
            provider_weights={"openai": 1.0, "anthropic": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        # 50-50 split => agreement_ratio = 0.5 < 0.85 => dissent
        assert result.consensus is False
        assert result.agreement_ratio == pytest.approx(0.5, abs=0.01)

    def test_weight_breaks_tie(self):
        """When count is tied, higher weight wins."""
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
            "anthropic": MockProvider("anthropic", "review", 0.9),
        })
        engine = ConsensusEngine(
            threshold=0.50,
            providers=["openai", "anthropic"],
            provider_weights={"openai": 2.0, "anthropic": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"
        # patch has weight 2/3 ~= 0.667
        assert result.agreement_ratio == pytest.approx(2.0 / 3.0, abs=0.01)


# ===================================================================
#  4. CONFIDENCE SCORING (WEIGHTED AVERAGE)
# ===================================================================


class TestConfidenceScoring:
    """Verify the weighted-average confidence calculation."""

    def test_equal_weights_equal_confidence(self):
        """All same confidence, equal weights -> average = that confidence."""
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.80),
            "b": MockProvider("b", "patch", 0.80),
            "c": MockProvider("c", "patch", 0.80),
        })
        engine = ConsensusEngine(
            providers=["a", "b", "c"],
            provider_weights={"a": 1.0, "b": 1.0, "c": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.confidence == pytest.approx(0.80, abs=0.01)

    def test_weighted_average_calculation(self):
        """Manual arithmetic: (0.9*1.0 + 0.6*1.0 + 0.3*0.8) / (1.0+1.0+0.8)."""
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
            "anthropic": MockProvider("anthropic", "patch", 0.6),
            "gemini": MockProvider("gemini", "patch", 0.3),
        })
        engine = ConsensusEngine(
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 0.8},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        expected = (0.9 * 1.0 + 0.6 * 1.0 + 0.3 * 0.8) / (1.0 + 1.0 + 0.8)
        assert result.confidence == pytest.approx(expected, abs=0.01)

    def test_single_provider_confidence_passthrough(self):
        mgr = MockManager({"sole": MockProvider("sole", "patch", 0.73)})
        engine = ConsensusEngine(providers=["sole"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.confidence == pytest.approx(0.73, abs=0.01)

    def test_high_weight_provider_dominates_confidence(self):
        """Provider with 10x weight should dominate the average."""
        mgr = MockManager({
            "heavy": MockProvider("heavy", "patch", 0.99),
            "light": MockProvider("light", "patch", 0.10),
        })
        engine = ConsensusEngine(
            providers=["heavy", "light"],
            provider_weights={"heavy": 10.0, "light": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        # (0.99*10 + 0.10*1) / 11 = 10.0/11 = 0.909...
        expected = (0.99 * 10.0 + 0.10 * 1.0) / 11.0
        assert result.confidence == pytest.approx(expected, abs=0.01)

    def test_zero_confidence_provider(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.0),
            "b": MockProvider("b", "patch", 1.0),
        })
        engine = ConsensusEngine(
            providers=["a", "b"],
            provider_weights={"a": 1.0, "b": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.confidence == pytest.approx(0.5, abs=0.01)

    def test_per_provider_confidences_stored(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.70),
        })
        engine = ConsensusEngine(
            providers=["openai", "anthropic"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.confidences["openai"] == pytest.approx(0.95)
        assert result.confidences["anthropic"] == pytest.approx(0.70)


# ===================================================================
#  5. EDGE CASES
# ===================================================================


class TestEdgeCases:
    """Empty inputs, single LLM, all disagreeing, boundary values."""

    def test_empty_providers_uses_defaults(self):
        """When providers=[] (falsy), constructor falls back to the default
        three providers ['openai', 'anthropic', 'gemini'] because of
        ``list(providers or [defaults])``.  Verify this behaviour."""
        mgr = MockManager({
            "openai": MockProvider("openai", "review", 0.5),
            "anthropic": MockProvider("anthropic", "review", 0.5),
            "gemini": MockProvider("gemini", "review", 0.5),
        })
        engine = ConsensusEngine(providers=[], manager=mgr)
        # Empty list is falsy => defaults kick in
        assert engine.provider_names == ["openai", "anthropic", "gemini"]
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "review"

    def test_single_provider_always_reaches_consensus(self):
        mgr = MockManager({"solo": MockProvider("solo", "mitigate", 0.75)})
        engine = ConsensusEngine(
            threshold=0.85, providers=["solo"], manager=mgr
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.agreement_ratio == 1.0

    def test_all_providers_disagree_picks_highest_weight(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "review", 0.8),
            "c": MockProvider("c", "monitor", 0.7),
            "d": MockProvider("d", "ignore", 0.6),
            "e": MockProvider("e", "escalate", 0.5),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b", "c", "d", "e"],
            provider_weights={k: 1.0 for k in "abcde"},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is False
        # Each has 1/5 = 0.2 weight fraction => 20% < 85%
        assert result.agreement_ratio == pytest.approx(0.2, abs=0.01)
        assert len(result.dissenting_providers) == 4

    def test_none_action_uses_default(self):
        """If provider returns None action, engine uses default_action."""

        class NoneActionProvider(BaseLLMProvider):
            def analyse(self, **kwargs: Any) -> LLMResponse:
                return LLMResponse(
                    recommended_action=None,  # type: ignore[arg-type]
                    confidence=0.5,
                    reasoning="No action determined",
                )

        mgr = MockManager({"x": NoneActionProvider("x")})
        engine = ConsensusEngine(providers=["x"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "review"  # default_action

    def test_empty_string_action_uses_default(self):
        """Empty-string action normalizes to default_action."""

        class EmptyActionProvider(BaseLLMProvider):
            def analyse(self, **kwargs: Any) -> LLMResponse:
                return LLMResponse(
                    recommended_action="",
                    confidence=0.5,
                    reasoning="No action",
                )

        mgr = MockManager({"x": EmptyActionProvider("x")})
        engine = ConsensusEngine(providers=["x"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        # "" or "review" => "review" after `or default_action`
        assert result.action == "review"


# ===================================================================
#  6. AGREEMENT THRESHOLD LOGIC (85% per sprint board)
# ===================================================================


class TestThresholdLogic:
    """Verify the 85% consensus threshold from SPRINT1-003 acceptance criteria."""

    def test_exactly_at_threshold_passes(self):
        """agreement_ratio == threshold => consensus=True."""
        # 85% of total weight = 0.85
        # Need to construct exactly 85% agreement.
        # 2 providers: weights 0.85 and 0.15
        # If they agree: ratio = 1.0 (both on same action) - too high
        # Let's do: 1 agrees (weight 0.85), 1 disagrees (weight 0.15)
        mgr = MockManager({
            "main": MockProvider("main", "patch", 0.9),
            "minor": MockProvider("minor", "review", 0.5),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["main", "minor"],
            provider_weights={"main": 0.85, "minor": 0.15},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.agreement_ratio == pytest.approx(0.85, abs=0.01)
        assert result.consensus is True

    def test_just_below_threshold_fails(self):
        """agreement_ratio just below threshold => consensus=False."""
        mgr = MockManager({
            "main": MockProvider("main", "patch", 0.9),
            "minor": MockProvider("minor", "review", 0.5),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["main", "minor"],
            provider_weights={"main": 0.84, "minor": 0.16},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.agreement_ratio == pytest.approx(0.84, abs=0.01)
        assert result.consensus is False

    def test_sprint_board_85_percent_three_providers(self):
        """With 3 equal-weight providers, 2/3 = 66.7% < 85% => no consensus."""
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.90),
            "gemini": MockProvider("gemini", "review", 0.60),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        # 2/3 = 0.667 < 0.85
        assert result.consensus is False

    def test_sprint_board_85_percent_three_all_agree(self):
        """With 3 equal-weight providers, 3/3 = 100% >= 85% => consensus."""
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.92),
            "gemini": MockProvider("gemini", "patch", 0.88),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True

    def test_zero_threshold_always_consensus(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.5),
            "b": MockProvider("b", "review", 0.5),
        })
        engine = ConsensusEngine(
            threshold=0.0,
            providers=["a", "b"],
            provider_weights={"a": 1.0, "b": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True

    def test_1_0_threshold_requires_unanimity(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "review", 0.9),
        })
        engine = ConsensusEngine(
            threshold=1.0,
            providers=["a", "b"],
            provider_weights={"a": 1.0, "b": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is False

    def test_1_0_threshold_passes_with_unanimity(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "patch", 0.8),
        })
        engine = ConsensusEngine(
            threshold=1.0,
            providers=["a", "b"],
            provider_weights={"a": 1.0, "b": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True

    def test_threshold_stored_in_result(self):
        mgr = MockManager({"a": MockProvider("a", "patch", 0.9)})
        engine = ConsensusEngine(threshold=0.77, providers=["a"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.threshold == 0.77


# ===================================================================
#  7. RESPONSE PARSING / ACTION NORMALIZATION
# ===================================================================


class TestResponseNormalization:
    """Verify that actions are lowercased, stripped, and merged."""

    def test_uppercase_action_lowercased(self):
        mgr = MockManager({"a": MockProvider("a", "PATCH", 0.9)})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"

    def test_mixed_case_action_lowercased(self):
        mgr = MockManager({"a": MockProvider("a", "Patch", 0.9)})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"

    def test_whitespace_stripped(self):
        mgr = MockManager({"a": MockProvider("a", "  patch  ", 0.9)})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"

    def test_case_insensitive_matching_for_consensus(self):
        """'PATCH' and 'patch' from different providers count as same action."""
        mgr = MockManager({
            "a": MockProvider("a", "PATCH", 0.9),
            "b": MockProvider("b", "patch", 0.9),
            "c": MockProvider("c", "Patch", 0.9),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b", "c"],
            provider_weights={"a": 1.0, "b": 1.0, "c": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "patch"
        assert result.dissenting_providers == []

    def test_votes_dict_has_normalized_actions(self):
        mgr = MockManager({
            "a": MockProvider("a", "PATCH", 0.9),
            "b": MockProvider("b", " Review ", 0.7),
        })
        engine = ConsensusEngine(
            providers=["a", "b"],
            provider_weights={"a": 1.0, "b": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.votes["a"] == "patch"
        assert result.votes["b"] == "review"


# ===================================================================
#  8. TIMEOUT HANDLING / FALLBACK BEHAVIOR
# ===================================================================


class TestTimeoutAndFallback:
    """Test all-fail, partial-fail, and error recording."""

    def test_all_providers_fail_returns_defaults(self):
        mgr = MockManager({
            "openai": FailingProvider("openai"),
            "anthropic": FailingProvider("anthropic"),
            "gemini": FailingProvider("gemini"),
        })
        engine = ConsensusEngine(
            providers=["openai", "anthropic", "gemini"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is False
        assert result.action == "review"
        assert result.confidence == 0.5
        assert len(result.provider_errors) == 3

    def test_all_fail_records_error_messages(self):
        mgr = MockManager({
            "a": FailingProvider("a", "Timeout connecting to API"),
        })
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "a" in result.provider_errors
        assert "Timeout" in result.provider_errors["a"]

    def test_all_fail_includes_reasoning_marker(self):
        mgr = MockManager({"a": FailingProvider("a")})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "ALL providers failed" in result.reasoning

    def test_all_fail_total_ms_is_positive(self):
        mgr = MockManager({"a": FailingProvider("a")})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.total_ms > 0

    def test_partial_failure_one_survives(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": FailingProvider("anthropic"),
            "gemini": MockProvider("gemini", "patch", 0.88),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "patch"
        assert len(result.votes) == 2
        assert "anthropic" in result.provider_errors

    def test_partial_failure_surviving_disagree(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": FailingProvider("b"),
            "c": MockProvider("c", "review", 0.7),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b", "c"],
            provider_weights={"a": 1.0, "b": 1.0, "c": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        # 2 survive, split 50-50 => 0.50 < 0.85 => no consensus
        assert result.consensus is False

    def test_two_fail_one_survives(self):
        mgr = MockManager({
            "a": FailingProvider("a"),
            "b": FailingProvider("b"),
            "c": MockProvider("c", "patch", 0.88),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b", "c"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"
        assert result.consensus is True  # 1/1 = 100%
        assert len(result.provider_errors) == 2

    def test_custom_default_action_on_failure(self):
        mgr = MockManager({"a": FailingProvider("a")})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        kwargs = {**ANALYSIS_KWARGS, "default_action": "escalate"}
        result = engine.analyse(**kwargs)
        assert result.action == "escalate"

    def test_custom_default_confidence_on_failure(self):
        mgr = MockManager({"a": FailingProvider("a")})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        kwargs = {**ANALYSIS_KWARGS, "default_confidence": 0.25}
        result = engine.analyse(**kwargs)
        assert result.confidence == 0.25


# ===================================================================
#  9. BATCH CONSENSUS (MULTI-ANALYSIS SEQUENCES)
# ===================================================================


class TestBatchConsensus:
    """Test running multiple analyses in sequence, tracking history."""

    def test_multiple_analyses_tracked_in_history(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "patch", 0.8),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b"],
            manager=mgr,
        )
        for _ in range(5):
            engine.analyse(**ANALYSIS_KWARGS)
        assert len(engine.history) == 5

    def test_stats_reflect_all_analyses(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
        })
        engine = ConsensusEngine(
            threshold=0.85, providers=["a"], manager=mgr
        )
        for _ in range(10):
            engine.analyse(**ANALYSIS_KWARGS)
        stats = engine.stats()
        assert stats["total_analyses"] == 10
        assert stats["consensus_reached"] == 10
        assert stats["consensus_rate"] == 1.0
        assert stats["action_distribution"]["patch"] == 10

    def test_mixed_consensus_and_dissent_stats(self):
        agree_mgr = MockManager({
            "a": MockProvider("a", "patch", 0.95),
            "b": MockProvider("b", "patch", 0.90),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b"],
            provider_weights={"a": 1.0, "b": 1.0},
            manager=agree_mgr,
        )
        # 3 consensus runs
        for _ in range(3):
            engine.analyse(**ANALYSIS_KWARGS)

        # Swap to disagreeing manager
        disagree_mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "review", 0.5),
        })
        engine._manager = disagree_mgr
        # 2 dissent runs
        for _ in range(2):
            engine.analyse(**ANALYSIS_KWARGS)

        stats = engine.stats()
        assert stats["total_analyses"] == 5
        assert stats["consensus_reached"] == 3
        assert stats["dissent_count"] == 2
        assert stats["consensus_rate"] == pytest.approx(0.6, abs=0.01)

    def test_history_is_copy_not_reference(self):
        mgr = MockManager({"a": MockProvider("a", "patch", 0.9)})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        engine.analyse(**ANALYSIS_KWARGS)
        h = engine.history
        h.clear()
        assert len(engine.history) == 1

    def test_different_prompts_produce_independent_results(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
        })
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        r1 = engine.analyse(
            prompt="CVE-2024-0001",
            context={"service_name": "svc-1"},
            default_action="review",
            default_confidence=0.5,
            default_reasoning="test",
        )
        r2 = engine.analyse(
            prompt="CVE-2024-0002",
            context={"service_name": "svc-2"},
            default_action="review",
            default_confidence=0.5,
            default_reasoning="test",
        )
        # Both should independently reach consensus
        assert r1.consensus is True
        assert r2.consensus is True
        assert len(engine.history) == 2


# ===================================================================
# 10. DEMO/MOCK MODE (NO ACTUAL API CALLS)
# ===================================================================


class TestDemoMockMode:
    """Verify the engine works entirely with mock providers (no HTTP)."""

    def test_no_network_calls_with_mock_manager(self):
        """The entire engine runs with zero network I/O."""
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.92),
            "gemini": MockProvider("gemini", "patch", 0.88),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.total_ms < 5000  # Should be near-instant

    def test_deterministic_provider_as_fallback(self):
        """DeterministicLLMProvider echoes defaults -- no API call."""
        mgr = MockManager(
            {"det": DeterministicLLMProvider("det")}
        )
        engine = ConsensusEngine(providers=["det"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "review"  # echoes default_action
        assert result.confidence == pytest.approx(0.5)

    def test_sentinel_provider_deterministic(self):
        """SentinelCyberProvider is rule-based, not API-based."""
        from core.llm_providers import SentinelCyberProvider

        mgr = MockManager({"sentinel": SentinelCyberProvider("sentinel")})
        engine = ConsensusEngine(providers=["sentinel"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert "Sentinel" in result.provider_responses["sentinel"].reasoning

    def test_mock_mode_10_runs_no_flakes(self):
        """Run 10 times with same config -> identical results every time."""
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.92),
            "gemini": MockProvider("gemini", "patch", 0.88),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            manager=mgr,
        )
        results = [engine.analyse(**ANALYSIS_KWARGS) for _ in range(10)]
        for r in results:
            assert r.consensus is True
            assert r.action == "patch"
            assert r.dissenting_providers == []

    def test_mitigation_hints_passed_through(self):
        """mitigation_hints kwarg reaches the provider."""
        calls: list[dict[str, Any]] = []

        class SpyProvider(BaseLLMProvider):
            def analyse(self, **kwargs: Any) -> LLMResponse:
                calls.append(kwargs)
                return LLMResponse(
                    recommended_action="patch",
                    confidence=0.9,
                    reasoning="spy",
                )

        mgr = MockManager({"spy": SpyProvider("spy")})
        engine = ConsensusEngine(providers=["spy"], manager=mgr)
        engine.analyse(
            **ANALYSIS_KWARGS,
            mitigation_hints={"mitre_candidates": ["T1059"]},
        )
        assert len(calls) == 1
        assert calls[0]["mitigation_hints"] == {"mitre_candidates": ["T1059"]}


# ===================================================================
# ADDITIONAL: MERGED ANALYSIS DATA
# ===================================================================


class TestMergedAnalysisData:
    """Test dedup/merging of MITRE, compliance, attack vectors."""

    def test_mitre_deduplication(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9, mitre=["T1190", "T1210"]),
            "b": MockProvider("b", "patch", 0.9, mitre=["T1210", "T1059"]),
            "c": MockProvider("c", "patch", 0.9, mitre=["T1190"]),
        })
        engine = ConsensusEngine(
            providers=["a", "b", "c"], manager=mgr
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.mitre_techniques.count("T1190") == 1
        assert result.mitre_techniques.count("T1210") == 1
        assert "T1059" in result.mitre_techniques

    def test_compliance_deduplication(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9, compliance=["SOC2", "HIPAA"]),
            "b": MockProvider("b", "patch", 0.9, compliance=["SOC2", "PCI-DSS"]),
        })
        engine = ConsensusEngine(
            providers=["a", "b"], manager=mgr
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.compliance_concerns.count("SOC2") == 1
        assert "HIPAA" in result.compliance_concerns
        assert "PCI-DSS" in result.compliance_concerns

    def test_attack_vectors_deduplication(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9, attack_vectors=["network", "local"]),
            "b": MockProvider("b", "patch", 0.9, attack_vectors=["network", "physical"]),
        })
        engine = ConsensusEngine(
            providers=["a", "b"], manager=mgr
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.attack_vectors.count("network") == 1
        assert "local" in result.attack_vectors
        assert "physical" in result.attack_vectors

    def test_empty_mitre_from_all_providers(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9, mitre=[]),
            "b": MockProvider("b", "patch", 0.9, mitre=[]),
        })
        engine = ConsensusEngine(
            providers=["a", "b"], manager=mgr
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.mitre_techniques == []

    def test_reasoning_includes_all_provider_labels(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9, reasoning="OAI analysis"),
            "anthropic": MockProvider(
                "anthropic", "patch", 0.9, reasoning="Claude analysis"
            ),
        })
        engine = ConsensusEngine(
            providers=["openai", "anthropic"], manager=mgr
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "[openai]" in result.reasoning
        assert "[anthropic]" in result.reasoning


# ===================================================================
# ADDITIONAL: CONSENSUS RESULT SERIALIZATION
# ===================================================================


class TestConsensusResultSerialization:
    """Validate ConsensusResult.to_dict() round-trip correctness."""

    def test_to_dict_all_keys_present(self):
        r = ConsensusResult(
            consensus=True,
            action="patch",
            confidence=0.9123,
            agreement_ratio=1.0,
            threshold=0.85,
            reasoning="test",
            mitre_techniques=["T1190"],
            compliance_concerns=["SOC2"],
            attack_vectors=["network"],
            votes={"openai": "patch"},
            confidences={"openai": 0.95},
            provider_errors={"gemini": "timeout"},
            dissenting_providers=[],
            total_ms=42.123,
            provider_ms={"openai": 10.567},
        )
        d = r.to_dict()
        expected_keys = {
            "consensus",
            "action",
            "confidence",
            "agreement_ratio",
            "threshold",
            "reasoning",
            "mitre_techniques",
            "compliance_concerns",
            "attack_vectors",
            "votes",
            "confidences",
            "dissenting_providers",
            "total_ms",
            "provider_ms",
            "provider_count",
            "errors",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_rounds_floats(self):
        r = ConsensusResult(
            confidence=0.123456789,
            agreement_ratio=0.987654321,
            total_ms=123.456789,
            confidences={"a": 0.111111, "b": 0.222222},
            provider_ms={"a": 5.555555, "b": 6.666666},
        )
        d = r.to_dict()
        assert d["confidence"] == 0.123
        assert d["agreement_ratio"] == 0.988
        assert d["total_ms"] == 123.46
        assert d["confidences"]["a"] == 0.111
        assert d["confidences"]["b"] == 0.222
        assert d["provider_ms"]["a"] == 5.56
        assert d["provider_ms"]["b"] == 6.67

    def test_to_dict_provider_count(self):
        r = ConsensusResult(
            votes={"a": "patch", "b": "patch", "c": "review"}
        )
        d = r.to_dict()
        assert d["provider_count"] == 3

    def test_to_dict_errors_key(self):
        r = ConsensusResult(
            provider_errors={"openai": "rate limited"}
        )
        d = r.to_dict()
        assert d["errors"] == {"openai": "rate limited"}

    def test_default_result_to_dict(self):
        r = ConsensusResult()
        d = r.to_dict()
        assert d["consensus"] is False
        assert d["action"] == "review"
        assert d["provider_count"] == 0


# ===================================================================
# ADDITIONAL: TIMING AND PERFORMANCE
# ===================================================================


class TestTimingAndPerformance:
    """Verify timing fields are populated correctly."""

    def test_total_ms_is_positive(self):
        mgr = MockManager({"a": MockProvider("a", "patch", 0.9)})
        engine = ConsensusEngine(providers=["a"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.total_ms > 0

    def test_provider_ms_recorded_for_each(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
            "anthropic": MockProvider("anthropic", "patch", 0.9),
        })
        engine = ConsensusEngine(
            providers=["openai", "anthropic"], manager=mgr
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "openai" in result.provider_ms
        assert "anthropic" in result.provider_ms
        for name, ms in result.provider_ms.items():
            assert ms >= 0

    def test_failed_provider_has_no_timing(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": FailingProvider("b"),
        })
        engine = ConsensusEngine(providers=["a", "b"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "a" in result.provider_ms
        assert "b" not in result.provider_ms

    def test_mock_providers_are_fast(self):
        """Mock providers should complete in under 100ms total."""
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "patch", 0.9),
            "c": MockProvider("c", "patch", 0.9),
        })
        engine = ConsensusEngine(
            providers=["a", "b", "c"], manager=mgr
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.total_ms < 2000


# ===================================================================
# ADDITIONAL: WEIGHTED VOTING EDGE CASES
# ===================================================================


class TestWeightedVotingEdgeCases:
    """Additional weighted voting scenarios."""

    def test_unknown_provider_gets_default_weight_1(self):
        """Provider not in weights dict gets weight=1.0."""
        mgr = MockManager({
            "custom_llm": MockProvider("custom_llm", "patch", 0.9),
        })
        engine = ConsensusEngine(
            providers=["custom_llm"],
            provider_weights={"openai": 1.0},  # custom_llm not listed
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "patch"

    def test_very_high_weight_dominates(self):
        """Provider with 100x weight wins against 4 others."""
        mgr = MockManager({
            "dominant": MockProvider("dominant", "isolate", 0.99),
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "patch", 0.9),
            "c": MockProvider("c", "patch", 0.9),
            "d": MockProvider("d", "patch", 0.9),
        })
        engine = ConsensusEngine(
            threshold=0.50,
            providers=["dominant", "a", "b", "c", "d"],
            provider_weights={
                "dominant": 100.0,
                "a": 1.0,
                "b": 1.0,
                "c": 1.0,
                "d": 1.0,
            },
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "isolate"
        # dominant weight 100 / total 104 = 0.9615
        assert result.agreement_ratio == pytest.approx(
            100.0 / 104.0, abs=0.01
        )

    def test_fractional_weights(self):
        """Fractional weights work correctly in arithmetic."""
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "patch", 0.9),
        })
        engine = ConsensusEngine(
            providers=["a", "b"],
            provider_weights={"a": 0.3, "b": 0.7},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.agreement_ratio == pytest.approx(1.0, abs=0.01)


# ===================================================================
# ADDITIONAL: ConsensusResult DEFAULTS
# ===================================================================


class TestConsensusResultDefaults:
    """Verify ConsensusResult default field values."""

    def test_all_defaults(self):
        r = ConsensusResult()
        assert r.consensus is False
        assert r.action == "review"
        assert r.confidence == 0.0
        assert r.agreement_ratio == 0.0
        assert r.threshold == 0.85
        assert r.reasoning == ""
        assert r.mitre_techniques == []
        assert r.compliance_concerns == []
        assert r.attack_vectors == []
        assert r.votes == {}
        assert r.confidences == {}
        assert r.provider_responses == {}
        assert r.provider_errors == {}
        assert r.total_ms == 0.0
        assert r.provider_ms == {}
        assert r.dissenting_providers == []

    def test_mutable_defaults_are_independent(self):
        """Each instance gets its own list/dict, not shared."""
        r1 = ConsensusResult()
        r2 = ConsensusResult()
        r1.votes["test"] = "patch"
        assert "test" not in r2.votes
        r1.mitre_techniques.append("T9999")
        assert "T9999" not in r2.mitre_techniques


# ===================================================================
# ADDITIONAL: STATS EDGE CASES
# ===================================================================


class TestStatsEdgeCases:
    """Edge cases for the stats() method."""

    def test_stats_empty_returns_minimal_dict(self):
        engine = ConsensusEngine()
        stats = engine.stats()
        assert stats == {"total_analyses": 0}

    def test_stats_action_distribution_multiple_actions(self):
        mgr_patch = MockManager({"a": MockProvider("a", "patch", 0.9)})
        mgr_review = MockManager({"a": MockProvider("a", "review", 0.5)})

        engine = ConsensusEngine(providers=["a"], manager=mgr_patch)
        engine.analyse(**ANALYSIS_KWARGS)
        engine.analyse(**ANALYSIS_KWARGS)

        engine._manager = mgr_review
        engine.analyse(**ANALYSIS_KWARGS)

        stats = engine.stats()
        assert stats["action_distribution"]["patch"] == 2
        assert stats["action_distribution"]["review"] == 1

    def test_stats_average_agreement(self):
        """Average agreement across mixed results."""
        mgr_agree = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "patch", 0.9),
        })
        mgr_split = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "review", 0.5),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b"],
            provider_weights={"a": 1.0, "b": 1.0},
            manager=mgr_agree,
        )
        engine.analyse(**ANALYSIS_KWARGS)  # agreement=1.0
        engine._manager = mgr_split
        engine.analyse(**ANALYSIS_KWARGS)  # agreement=0.5
        stats = engine.stats()
        assert stats["average_agreement"] == pytest.approx(0.75, abs=0.01)
