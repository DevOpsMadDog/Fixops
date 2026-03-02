"""
Tests for the Multi-LLM Consensus Engine.

Covers:
  - Unanimous consensus (all providers agree)
  - Majority consensus (threshold met)
  - Dissent (threshold NOT met)
  - Single-provider fallback
  - All-providers-failed fallback
  - Weighted voting
  - Stats tracking
  - Merged MITRE / compliance / attack vectors
"""

from __future__ import annotations

import pytest

from core.llm_consensus import ConsensusEngine
from core.llm_providers import (
    BaseLLMProvider,
    LLMProviderManager,
    LLMResponse,
)


# ---------------------------------------------------------------------------
# Mock providers for deterministic testing
# ---------------------------------------------------------------------------


class MockProvider(BaseLLMProvider):
    """Provider that returns a fixed action."""

    def __init__(self, name: str, action: str, confidence: float = 0.9, **kwargs):
        super().__init__(name)
        self._action = action
        self._confidence = confidence
        self._mitre = kwargs.get("mitre", [])
        self._compliance = kwargs.get("compliance", [])

    def analyse(self, *, prompt, context, default_action, default_confidence, default_reasoning, mitigation_hints=None):
        return LLMResponse(
            recommended_action=self._action,
            confidence=self._confidence,
            reasoning=f"Mock {self.name}: recommending {self._action}",
            mitre_techniques=self._mitre,
            compliance_concerns=self._compliance,
        )


class FailingProvider(BaseLLMProvider):
    """Provider that always raises."""

    def analyse(self, **kwargs):
        raise RuntimeError(f"Provider {self.name} is down")


class MockManager(LLMProviderManager):
    """Manager that returns mock providers."""

    def __init__(self, providers: dict[str, BaseLLMProvider]):
        super().__init__()
        self.providers = providers


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def all_agree_manager():
    return MockManager({
        "openai": MockProvider("openai", "patch", 0.95, mitre=["T1190"]),
        "anthropic": MockProvider("anthropic", "patch", 0.92, compliance=["SOC2"]),
        "gemini": MockProvider("gemini", "patch", 0.88),
    })


@pytest.fixture
def majority_manager():
    return MockManager({
        "openai": MockProvider("openai", "patch", 0.95),
        "anthropic": MockProvider("anthropic", "patch", 0.90),
        "gemini": MockProvider("gemini", "review", 0.60),  # dissents
    })


@pytest.fixture
def split_manager():
    return MockManager({
        "openai": MockProvider("openai", "patch", 0.95),
        "anthropic": MockProvider("anthropic", "review", 0.60),
        "gemini": MockProvider("gemini", "monitor", 0.40),
    })


@pytest.fixture
def all_fail_manager():
    return MockManager({
        "openai": FailingProvider("openai"),
        "anthropic": FailingProvider("anthropic"),
        "gemini": FailingProvider("gemini"),
    })


ANALYSIS_KWARGS = {
    "prompt": "Analyse CVE-2024-TEST",
    "context": {"service_name": "aldeci-core"},
    "default_action": "review",
    "default_confidence": 0.5,
    "default_reasoning": "Heuristic fallback",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUnanimousConsensus:
    def test_all_agree_reaches_consensus(self, all_agree_manager):
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            manager=all_agree_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "patch"
        assert result.agreement_ratio >= 0.99
        assert len(result.dissenting_providers) == 0

    def test_confidence_is_weighted_average(self, all_agree_manager):
        engine = ConsensusEngine(
            providers=["openai", "anthropic", "gemini"],
            manager=all_agree_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert 0.85 <= result.confidence <= 1.0

    def test_merges_mitre_and_compliance(self, all_agree_manager):
        engine = ConsensusEngine(
            providers=["openai", "anthropic", "gemini"],
            manager=all_agree_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert "T1190" in result.mitre_techniques
        assert "SOC2" in result.compliance_concerns


class TestMajorityConsensus:
    def test_majority_with_equal_weights(self, majority_manager):
        engine = ConsensusEngine(
            threshold=0.60,  # Lower threshold: 2/3 ≈ 66% should pass
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=majority_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"
        assert result.consensus is True
        assert "gemini" in result.dissenting_providers

    def test_high_threshold_causes_dissent(self, majority_manager):
        engine = ConsensusEngine(
            threshold=0.90,  # 2/3=0.67 < 0.90 → dissent
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=majority_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        # With equal weights, 2/3 ≈ 0.67 < 0.90
        assert result.consensus is False


class TestDissent:
    def test_three_way_split_fails_consensus(self, split_manager):
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=split_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is False
        assert len(result.dissenting_providers) >= 2
        assert "DISSENT" in result.reasoning


class TestWeightedVoting:
    def test_heavier_provider_wins(self):
        manager = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": MockProvider("anthropic", "review", 0.90),
            "gemini": MockProvider("gemini", "review", 0.85),
        })
        # Give OpenAI 10x weight → "patch" wins despite 2 "review" votes
        engine = ConsensusEngine(
            threshold=0.50,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 10.0, "anthropic": 1.0, "gemini": 1.0},
            manager=manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.action == "patch"


class TestAllProvidersFail:
    def test_all_fail_returns_default(self, all_fail_manager):
        engine = ConsensusEngine(
            providers=["openai", "anthropic", "gemini"],
            manager=all_fail_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is False
        assert result.action == "review"  # default_action
        assert len(result.provider_errors) == 3


class TestPartialFailure:
    def test_one_provider_fails_others_vote(self):
        manager = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
            "anthropic": FailingProvider("anthropic"),
            "gemini": MockProvider("gemini", "patch", 0.88),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            manager=manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "patch"
        assert "anthropic" in result.provider_errors
        assert len(result.votes) == 2


class TestConsensusStats:
    def test_empty_stats(self):
        engine = ConsensusEngine()
        stats = engine.stats()
        assert stats["total_analyses"] == 0

    def test_stats_after_multiple_analyses(self, all_agree_manager):
        engine = ConsensusEngine(
            providers=["openai", "anthropic", "gemini"],
            manager=all_agree_manager,
        )
        for _ in range(3):
            engine.analyse(**ANALYSIS_KWARGS)
        stats = engine.stats()
        assert stats["total_analyses"] == 3
        assert stats["consensus_reached"] == 3
        assert stats["consensus_rate"] == 1.0
        assert "patch" in stats["action_distribution"]


class TestConsensusResultSerialization:
    def test_to_dict(self, all_agree_manager):
        engine = ConsensusEngine(
            providers=["openai", "anthropic", "gemini"],
            manager=all_agree_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        d = result.to_dict()
        assert "consensus" in d
        assert "action" in d
        assert "agreement_ratio" in d
        assert "votes" in d
        assert d["provider_count"] == 3

    def test_dissent_to_dict(self, split_manager):
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai", "anthropic", "gemini"],
            provider_weights={"openai": 1.0, "anthropic": 1.0, "gemini": 1.0},
            manager=split_manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        d = result.to_dict()
        assert d["consensus"] is False
        assert len(d["dissenting_providers"]) >= 2


class TestSingleProvider:
    def test_single_provider_always_consensus(self):
        manager = MockManager({
            "openai": MockProvider("openai", "patch", 0.95),
        })
        engine = ConsensusEngine(
            threshold=0.85,
            providers=["openai"],
            manager=manager,
        )
        result = engine.analyse(**ANALYSIS_KWARGS)
        assert result.consensus is True
        assert result.action == "patch"
        assert result.agreement_ratio == 1.0
