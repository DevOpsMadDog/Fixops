"""
Comprehensive unit tests for the Multi-LLM Consensus Engine
(suite-core/core/llm_consensus.py).

Covers:
  - ConsensusResult default values and to_dict()
  - Unanimous consensus: all agree, confidence averaging
  - Majority consensus: threshold met with dissenters
  - Dissent: threshold NOT met
  - Weighted voting: heavy provider wins despite minority
  - All providers fail: deterministic fallback
  - Partial failure: surviving providers vote
  - Single provider: always reaches consensus
  - Edge cases: empty providers list, zero threshold, 1.0 threshold
  - Merged MITRE techniques, compliance concerns, attack vectors
  - Stats tracking after multiple analyses
  - History management
  - DEFAULT_PROVIDER_WEIGHTS structure
  - _vote method behaviour via ConsensusEngine
"""

from __future__ import annotations


from core.llm_consensus import (
    ConsensusEngine,
    ConsensusResult,
    DEFAULT_PROVIDER_WEIGHTS,
)
from core.llm_providers import (
    BaseLLMProvider,
    LLMProviderManager,
    LLMResponse,
)


# ---------------------------------------------------------------------------
# Test helpers / mock providers
# ---------------------------------------------------------------------------


class MockProvider(BaseLLMProvider):
    """Provider that returns a fixed action."""

    def __init__(
        self,
        name: str,
        action: str,
        confidence: float = 0.9,
        *,
        mitre: list | None = None,
        compliance: list | None = None,
        attack_vectors: list | None = None,
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
        prompt,
        context,
        default_action,
        default_confidence,
        default_reasoning,
        mitigation_hints=None,
    ):
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

    def analyse(self, **kwargs):
        raise RuntimeError(f"Provider {self.name} is down")


class SlowMockProvider(MockProvider):
    """Provider that works but simulates being slow (for timing checks)."""

    pass


class MockManager(LLMProviderManager):
    """Manager that returns specific mock providers."""

    def __init__(self, providers: dict[str, BaseLLMProvider]):
        super().__init__()
        self.providers = providers


# ---------------------------------------------------------------------------
# Shared analysis kwargs
# ---------------------------------------------------------------------------

ANALYSIS_KWARGS = {
    "prompt": "Analyse CVE-2024-TEST for risk assessment",
    "context": {"service_name": "api-gateway", "environment": "production"},
    "default_action": "review",
    "default_confidence": 0.5,
    "default_reasoning": "Heuristic fallback analysis",
}


# ---------------------------------------------------------------------------
# ConsensusResult defaults
# ---------------------------------------------------------------------------


class TestConsensusResultDefaults:
    def test_default_values(self):
        r = ConsensusResult()
        assert r.consensus is False
        assert r.action == "review"
        assert r.confidence == 0.0
        assert r.agreement_ratio == 0.0
        assert r.threshold == 0.85
        assert r.votes == {}
        assert r.dissenting_providers == []
        assert r.total_ms == 0.0

    def test_to_dict_keys(self):
        r = ConsensusResult(
            consensus=True,
            action="patch",
            confidence=0.9,
            agreement_ratio=1.0,
            votes={"openai": "patch"},
            total_ms=42.0,
        )
        d = r.to_dict()
        expected_keys = {
            "consensus", "action", "confidence", "agreement_ratio",
            "threshold", "reasoning", "mitre_techniques",
            "compliance_concerns", "attack_vectors", "votes",
            "confidences", "dissenting_providers", "total_ms",
            "provider_ms", "provider_count", "errors",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_rounds_floats(self):
        r = ConsensusResult(
            confidence=0.123456789,
            agreement_ratio=0.987654321,
            total_ms=123.456789,
        )
        d = r.to_dict()
        assert d["confidence"] == 0.123
        assert d["agreement_ratio"] == 0.988
        assert d["total_ms"] == 123.46

    def test_provider_count_in_to_dict(self):
        r = ConsensusResult(votes={"a": "patch", "b": "patch", "c": "review"})
        d = r.to_dict()
        assert d["provider_count"] == 3


# ---------------------------------------------------------------------------
# Unanimous consensus tests
# ---------------------------------------------------------------------------


class TestUnanimousConsensus:
    def test_all_agree_reaches_consensus(self):
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
        assert result.agreement_ratio >= 0.99
        assert len(result.dissenting_providers) == 0

    def test_confidence_is_weighted_average(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.90),
            "gemini": MockProvider("gemini", "patch", 0.80),
        })
        engine = ConsensusEngine(
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 0.8},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        # Weighted avg: (0.95*1.0 + 0.90*1.0 + 0.80*0.8) / (1.0+1.0+0.8)
        expected = (0.95 + 0.90 + 0.80 * 0.8) / 2.8
        assert abs(result.confidence - expected) < 0.01

    def test_reasoning_includes_all_providers(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9, reasoning="OpenAI says patch"),
            "anthropic": MockProvider("anthropic", "patch", 0.9, reasoning="Claude says patch"),
        })
        engine = ConsensusEngine(
            providers=["openai", "anthropic"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "openai" in result.reasoning.lower() or "OpenAI" in result.reasoning
        assert "anthropic" in result.reasoning.lower() or "Claude" in result.reasoning


# ---------------------------------------------------------------------------
# Majority consensus
# ---------------------------------------------------------------------------


class TestMajorityConsensus:
    def test_two_of_three_with_low_threshold(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.90),
            "gemini": MockProvider("gemini", "review", 0.60),
        })
        engine = ConsensusEngine(
            threshold=0.60,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"
        assert result.consensus is True
        assert "gemini" in result.dissenting_providers

    def test_two_of_three_fails_high_threshold(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "patch", 0.90),
            "gemini": MockProvider("gemini", "review", 0.60),
        })
        engine = ConsensusEngine(
            threshold=0.90,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        # 2/3 = 0.667 < 0.90 => dissent
        assert result.consensus is False


# ---------------------------------------------------------------------------
# Three-way split / full dissent
# ---------------------------------------------------------------------------


class TestDissent:
    def test_three_way_split_no_consensus(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "review", 0.60),
            "gemini": MockProvider("gemini", "monitor", 0.40),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is False
        assert len(result.dissenting_providers) >= 2

    def test_dissent_reasoning_contains_warning(self):
        mgr = MockManager({
            "a": MockProvider("a", "patch", 0.9),
            "b": MockProvider("b", "review", 0.5),
            "c": MockProvider("c", "monitor", 0.3),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["a", "b", "c"],
            provider_weights={"a": 1.0, "b": 1.0, "c": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "DISSENT" in result.reasoning


# ---------------------------------------------------------------------------
# Weighted voting
# ---------------------------------------------------------------------------


class TestWeightedVoting:
    def test_heavy_weight_wins_minority(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "review", 0.90),
            "gemini": MockProvider("gemini", "review", 0.85),
        })
        # OpenAI has 10x weight => "patch" wins despite 2 "review" votes
        engine = ConsensusEngine(
            threshold=0.50,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 10.0, "anthropic": 1.0, "gemini": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"

    def test_default_weights_structure(self):
        assert "openai" in DEFAULT_PROVIDER_WEIGHTS
        assert "anthropic" in DEFAULT_PROVIDER_WEIGHTS
        assert "gemini" in DEFAULT_PROVIDER_WEIGHTS
        assert "sentinel" in DEFAULT_PROVIDER_WEIGHTS
        assert all(isinstance(v, float) for v in DEFAULT_PROVIDER_WEIGHTS.values())

    def test_unknown_provider_gets_weight_1(self):
        mgr = MockManager({
            "custom_llm": MockProvider("custom_llm", "patch", 0.9),
        })
        engine = ConsensusEngine(
            providers=["custom_llm"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        # Unknown provider should get default weight 1.0 in voting
        assert result.consensus is True
        assert result.action == "patch"


# ---------------------------------------------------------------------------
# All providers fail
# ---------------------------------------------------------------------------


class TestAllProvidersFail:
    def test_returns_default_action(self):
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

    def test_all_fail_includes_error_messages(self):
        mgr = MockManager({
            "openai": FailingProvider("openai"),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "openai" in result.provider_errors

    def test_all_fail_uses_default_reasoning(self):
        mgr = MockManager({
            "openai": FailingProvider("openai"),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "Heuristic fallback" in result.reasoning


# ---------------------------------------------------------------------------
# Partial failure
# ---------------------------------------------------------------------------


class TestPartialFailure:
    def test_one_fails_others_vote(self):
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
        assert "anthropic" in result.provider_errors
        assert len(result.votes) == 2

    def test_two_fail_one_survives(self):
        mgr = MockManager({
            "openai": FailingProvider("openai"),
            "anthropic": FailingProvider("anthropic"),
            "gemini": MockProvider("gemini", "patch", 0.88),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"
        assert len(result.votes) == 1
        assert len(result.provider_errors) == 2


# ---------------------------------------------------------------------------
# Single provider
# ---------------------------------------------------------------------------


class TestSingleProvider:
    def test_single_provider_always_consensus(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai"],
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "patch"
        assert result.agreement_ratio == 1.0

    def test_single_provider_confidence_preserved(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.73),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        # With only 1 provider and weight 1.0, confidence = 0.73
        assert abs(result.confidence - 0.73) < 0.01


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_zero_threshold_always_consensus(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.5),
            "anthropic": MockProvider("anthropic", "review", 0.5),
        })
        engine = ConsensusEngine(
            threshold=0.0,
            providers=["openai", "anthropic"],
            provider_weights={"openai": 1.0, "anthropic": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True

    def test_threshold_1_requires_unanimity(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
            "anthropic": MockProvider("anthropic", "review", 0.9),
        })
        engine = ConsensusEngine(
            threshold=1.0,
            providers=["openai", "anthropic"],
            provider_weights={"openai": 1.0, "anthropic": 1.0},
            manager=mgr,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is False

    def test_action_normalised_to_lowercase(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "PATCH", 0.9),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"

    def test_action_stripped_of_whitespace(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "  patch  ", 0.9),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"


# ---------------------------------------------------------------------------
# Merged analysis data
# ---------------------------------------------------------------------------


class TestMergedAnalysis:
    def test_mitre_techniques_merged(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9, mitre=["T1190", "T1210"]),
            "anthropic": MockProvider("anthropic", "patch", 0.9, mitre=["T1210", "T1059"]),
        })
        engine = ConsensusEngine(providers=["openai", "anthropic"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "T1190" in result.mitre_techniques
        assert "T1059" in result.mitre_techniques
        # Deduplication: T1210 should appear only once
        assert result.mitre_techniques.count("T1210") == 1

    def test_compliance_concerns_merged(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9, compliance=["SOC2"]),
            "anthropic": MockProvider("anthropic", "patch", 0.9, compliance=["PCI-DSS"]),
        })
        engine = ConsensusEngine(providers=["openai", "anthropic"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "SOC2" in result.compliance_concerns
        assert "PCI-DSS" in result.compliance_concerns

    def test_attack_vectors_merged(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9, attack_vectors=["network"]),
            "anthropic": MockProvider("anthropic", "patch", 0.9, attack_vectors=["local"]),
        })
        engine = ConsensusEngine(providers=["openai", "anthropic"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "network" in result.attack_vectors
        assert "local" in result.attack_vectors


# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------


class TestStatsTracking:
    def test_empty_stats(self):
        engine = ConsensusEngine()
        stats = engine.stats()
        assert stats["total_analyses"] == 0

    def test_stats_after_consensus(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        engine.analyse(**ANALYSIS_KWARGS)
        engine.analyse(**ANALYSIS_KWARGS)
        stats = engine.stats()
        assert stats["total_analyses"] == 2
        assert stats["consensus_reached"] == 2
        assert stats["dissent_count"] == 0
        assert stats["consensus_rate"] == 1.0
        assert stats["average_agreement"] == 1.0
        assert "patch" in stats["action_distribution"]
        assert stats["action_distribution"]["patch"] == 2

    def test_stats_after_mixed_results(self):
        agree_mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
        })
        disagree_mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
            "anthropic": MockProvider("anthropic", "review", 0.9),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai"],
            manager=agree_mgr,
        )
        engine.analyse(**ANALYSIS_KWARGS)
        # Now swap manager and add anthropic
        engine._manager = disagree_mgr
        engine.provider_names = ["openai", "anthropic"]
        engine.weights = {"openai": 1.0, "anthropic": 1.0}
        engine.analyse(**ANALYSIS_KWARGS)
        stats = engine.stats()
        assert stats["total_analyses"] == 2
        assert stats["consensus_reached"] == 1
        assert stats["dissent_count"] == 1

    def test_stats_average_latency(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        engine.analyse(**ANALYSIS_KWARGS)
        stats = engine.stats()
        assert stats["average_latency_ms"] >= 0.0


# ---------------------------------------------------------------------------
# History management
# ---------------------------------------------------------------------------


class TestHistory:
    def test_history_is_copy(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        engine.analyse(**ANALYSIS_KWARGS)
        h = engine.history
        h.clear()
        assert len(engine.history) == 1  # original unchanged

    def test_history_contains_results(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        engine.analyse(**ANALYSIS_KWARGS)
        assert len(engine.history) == 1
        assert engine.history[0].action == "patch"

    def test_total_ms_is_positive(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.total_ms > 0.0

    def test_provider_ms_recorded(self):
        mgr = MockManager({
            "openai": MockProvider("openai", "patch", 0.9),
        })
        engine = ConsensusEngine(providers=["openai"], manager=mgr)
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "openai" in result.provider_ms
        assert result.provider_ms["openai"] >= 0.0
