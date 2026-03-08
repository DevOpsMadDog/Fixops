"""Tests for AdvancedLLMEngine — multi-LLM consensus analysis."""
import asyncio

from core.services.enterprise.advanced_llm_engine import (
    LLMProvider,
    LLMAnalysisResult,
    MultiLLMResult,
    AdvancedLLMEngine,
)


class TestLLMProvider:
    def test_values(self):
        assert LLMProvider.OPENAI_CHATGPT.value == "openai_chatgpt"
        assert LLMProvider.ANTHROPIC_CLAUDE.value == "anthropic_claude"
        assert LLMProvider.GOOGLE_GEMINI.value == "google_gemini"
        assert LLMProvider.SPECIALIZED_CYBER.value == "specialized_cyber"

    def test_all_providers(self):
        assert len(LLMProvider) == 4


class TestLLMAnalysisResult:
    def test_create(self):
        result = LLMAnalysisResult(
            provider="openai_chatgpt",
            recommended_action="BLOCK",
            confidence=0.95,
            reasoning="Critical SQL injection detected",
            processing_time_ms=150.0,
        )
        assert result.provider == "openai_chatgpt"
        assert result.confidence == 0.95
        assert result.processing_time_ms == 150.0

    def test_different_providers(self):
        for provider in ["openai_chatgpt", "anthropic_claude", "google_gemini"]:
            result = LLMAnalysisResult(
                provider=provider,
                recommended_action="ALLOW",
                confidence=0.8,
                reasoning="Low risk finding",
                processing_time_ms=100.0,
            )
            assert result.provider == provider


class TestMultiLLMResult:
    def test_create(self):
        analysis = LLMAnalysisResult(
            provider="chatgpt", recommended_action="BLOCK",
            confidence=0.9, reasoning="High risk", processing_time_ms=100.0,
        )
        result = MultiLLMResult(
            individual_analyses=[analysis],
            final_decision="BLOCK",
            consensus_confidence=0.9,
            disagreement_areas=[],
            expert_validation_required=False,
        )
        assert result.final_decision == "BLOCK"
        assert len(result.individual_analyses) == 1
        assert not result.expert_validation_required

    def test_with_disagreement(self):
        a1 = LLMAnalysisResult(
            provider="chatgpt", recommended_action="BLOCK",
            confidence=0.8, reasoning="High risk", processing_time_ms=100.0,
        )
        a2 = LLMAnalysisResult(
            provider="claude", recommended_action="DEFER",
            confidence=0.6, reasoning="Needs review", processing_time_ms=150.0,
        )
        result = MultiLLMResult(
            individual_analyses=[a1, a2],
            final_decision="BLOCK",
            consensus_confidence=0.7,
            disagreement_areas=["action"],
            expert_validation_required=True,
        )
        assert result.expert_validation_required
        assert len(result.disagreement_areas) == 1


class TestAdvancedLLMEngine:
    def test_init(self):
        engine = AdvancedLLMEngine()
        assert engine is not None
        assert isinstance(engine.enabled_providers, list)
        assert len(engine.enabled_providers) > 0

    def test_get_supported_llms(self):
        engine = AdvancedLLMEngine()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(engine.get_supported_llms())
        finally:
            loop.close()
        assert isinstance(result, dict)
        assert "openai_chatgpt" in result
        assert "anthropic_claude" in result

    def test_initialize(self):
        engine = AdvancedLLMEngine()
        assert not engine.initialized
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(engine.initialize())
        finally:
            loop.close()
        assert engine.initialized

    def test_double_initialize(self):
        engine = AdvancedLLMEngine()
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(engine.initialize())
            loop.run_until_complete(engine.initialize())
        finally:
            loop.close()
        assert engine.initialized

    def test_no_llm_client_without_api_key(self):
        engine = AdvancedLLMEngine()
        # Without API key, llm_client should be None
        assert engine.llm_client is None
