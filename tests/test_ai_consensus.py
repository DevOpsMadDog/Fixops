"""Unit tests for Phase 2 AI Consensus features.

Tests cover:
- ConsensusConfig: Configuration loading and validation
- MultiAIOrchestrator: LLM integration, fallback logic, statistics
- Real LLM provider integration with mocked responses
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from core.llm_providers import LLMProviderManager, LLMResponse
from core.pentagi_advanced import (
    AIDecision,
    AIRole,
    ConsensusConfig,
    ConsensusDecision,
    LLMCallError,
    MultiAIOrchestrator,
)


class TestConsensusConfig:
    """Tests for ConsensusConfig dataclass."""

    def test_default_values(self):
        config = ConsensusConfig()
        assert config.threshold == 0.6
        assert config.weights["architect"] == 0.35
        assert config.weights["developer"] == 0.40
        assert config.weights["lead"] == 0.25
        assert config.timeout_seconds == 30.0
        assert config.max_retries == 3
        assert config.fallback_enabled is True

    def test_from_env(self):
        with patch.dict(
            os.environ,
            {
                "FIXOPS_CONSENSUS_THRESHOLD": "0.8",
                "FIXOPS_CONSENSUS_WEIGHTS_ARCHITECT": "0.30",
                "FIXOPS_CONSENSUS_WEIGHTS_DEVELOPER": "0.45",
                "FIXOPS_CONSENSUS_WEIGHTS_LEAD": "0.25",
                "FIXOPS_LLM_TIMEOUT": "60",
                "FIXOPS_LLM_MAX_RETRIES": "5",
                "FIXOPS_LLM_FALLBACK_ENABLED": "false",
            },
        ):
            config = ConsensusConfig.from_env()
            assert config.threshold == 0.8
            assert config.weights["architect"] == 0.30
            assert config.weights["developer"] == 0.45
            assert config.weights["lead"] == 0.25
            assert config.timeout_seconds == 60.0
            assert config.max_retries == 5
            assert config.fallback_enabled is False

    def test_validate_valid_config(self):
        config = ConsensusConfig()
        config.validate()

    def test_validate_invalid_threshold(self):
        config = ConsensusConfig(threshold=1.5)
        with pytest.raises(ValueError, match="threshold must be between 0 and 1"):
            config.validate()

    def test_validate_invalid_weights(self):
        config = ConsensusConfig(
            weights={
                "architect": 0.5,
                "developer": 0.5,
                "lead": 0.5,
            }
        )
        with pytest.raises(ValueError, match="weights must sum to 1.0"):
            config.validate()

    def test_validate_invalid_timeout(self):
        config = ConsensusConfig(timeout_seconds=-1)
        with pytest.raises(ValueError, match="Timeout must be positive"):
            config.validate()

    def test_validate_invalid_retries(self):
        config = ConsensusConfig(max_retries=-1)
        with pytest.raises(ValueError, match="Max retries must be non-negative"):
            config.validate()


class TestMultiAIOrchestrator:
    """Tests for MultiAIOrchestrator with mocked LLM providers."""

    @pytest.fixture
    def mock_llm_manager(self):
        manager = MagicMock(spec=LLMProviderManager)
        manager.analyse.return_value = LLMResponse(
            recommended_action="Proceed with testing",
            confidence=0.85,
            reasoning="Analysis indicates exploitable vulnerability",
            mitre_techniques=["T1190", "T1059"],
            compliance_concerns=["PCI-DSS"],
            attack_vectors=["injection"],
            metadata={"mode": "remote", "provider": "openai"},
        )
        return manager

    @pytest.fixture
    def orchestrator(self, mock_llm_manager):
        return MultiAIOrchestrator(mock_llm_manager)

    def test_initialization(self, orchestrator):
        assert orchestrator.config.threshold == 0.6
        assert len(orchestrator.decision_history) == 0
        assert orchestrator._call_count["total"] == 0

    def test_initialization_with_custom_config(self, mock_llm_manager):
        config = ConsensusConfig(threshold=0.8)
        orchestrator = MultiAIOrchestrator(mock_llm_manager, config=config)
        assert orchestrator.config.threshold == 0.8

    @pytest.mark.asyncio
    async def test_call_llm_success(self, orchestrator, mock_llm_manager):
        result = await orchestrator._call_llm("openai", "test prompt")

        mock_llm_manager.analyse.assert_called_once()
        assert orchestrator._call_count["total"] == 1
        assert orchestrator._call_count["success"] == 1

        parsed = json.loads(result)
        assert parsed["recommendation"] == "Proceed with testing"
        assert parsed["confidence"] == 0.85

    @pytest.mark.asyncio
    async def test_call_llm_fallback_response(self, orchestrator, mock_llm_manager):
        mock_llm_manager.analyse.return_value = LLMResponse(
            recommended_action="review",
            confidence=0.5,
            reasoning="Deterministic fallback",
            metadata={"mode": "deterministic", "reason": "provider_disabled"},
        )

        result = await orchestrator._call_llm("openai", "test prompt")

        assert orchestrator._call_count["fallback"] == 1
        parsed = json.loads(result)
        assert parsed["confidence"] == 0.5

    @pytest.mark.asyncio
    async def test_call_llm_error_with_fallback(self, orchestrator, mock_llm_manager):
        mock_llm_manager.analyse.side_effect = Exception("API error")

        result = await orchestrator._call_llm("openai", "test prompt")

        assert orchestrator._call_count["fallback"] == 1
        parsed = json.loads(result)
        assert parsed["metadata"]["fallback"] is True
        assert "API error" in parsed["reasoning"]

    @pytest.mark.asyncio
    async def test_call_llm_error_without_fallback(self, mock_llm_manager):
        config = ConsensusConfig(fallback_enabled=False)
        orchestrator = MultiAIOrchestrator(mock_llm_manager, config=config)
        mock_llm_manager.analyse.side_effect = Exception("API error")

        with pytest.raises(LLMCallError):
            await orchestrator._call_llm("openai", "test prompt")

    @pytest.mark.asyncio
    async def test_call_llm_timeout_with_fallback(self, mock_llm_manager, caplog):
        """Test _call_llm handles asyncio.TimeoutError with fallback.

        Covers lines 458, 461 in pentagi_advanced.py - the timeout error handling
        that creates a TimeoutError with message and logs a warning.
        """
        import asyncio
        from unittest.mock import patch

        # Configure with short timeout and single retry for faster test
        config = ConsensusConfig(
            timeout_seconds=0.01,
            max_retries=1,
            fallback_enabled=True,
        )
        orchestrator = MultiAIOrchestrator(mock_llm_manager, config=config)

        # Patch asyncio.wait_for to raise TimeoutError
        async def mock_wait_for(coro, timeout):
            # Cancel the coroutine to avoid warnings
            coro.close()
            raise asyncio.TimeoutError()

        with patch("core.pentagi_advanced.asyncio.wait_for", mock_wait_for):
            result = await orchestrator._call_llm("openai", "test prompt")

        # Should return fallback response
        parsed = json.loads(result)
        assert parsed["metadata"]["fallback"] is True
        assert "timed out" in parsed["reasoning"].lower()

        # Verify timeout warning was logged
        assert any("timed out" in record.message.lower() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_get_architect_decision(self, orchestrator, mock_llm_manager):
        context = {"service_name": "test-service"}
        vulnerability = {"id": "CVE-2024-1234", "severity": "high"}

        decision = await orchestrator.get_architect_decision(context, vulnerability)

        assert decision.role == AIRole.ARCHITECT
        assert decision.confidence > 0
        assert decision.recommendation

    @pytest.mark.asyncio
    async def test_get_developer_decision(self, orchestrator, mock_llm_manager):
        context = {"service_name": "test-service"}
        vulnerability = {"id": "CVE-2024-1234", "severity": "high"}

        decision = await orchestrator.get_developer_decision(context, vulnerability)

        assert decision.role == AIRole.DEVELOPER
        assert decision.confidence > 0

    @pytest.mark.asyncio
    async def test_get_lead_decision(self, orchestrator, mock_llm_manager):
        context = {"service_name": "test-service"}
        vulnerability = {"id": "CVE-2024-1234", "severity": "high"}

        decision = await orchestrator.get_lead_decision(context, vulnerability)

        assert decision.role == AIRole.LEAD
        assert decision.confidence > 0

    @pytest.mark.asyncio
    async def test_compose_consensus(self, orchestrator, mock_llm_manager):
        architect = AIDecision(
            role=AIRole.ARCHITECT,
            recommendation="Test",
            confidence=0.8,
            reasoning="Architect analysis",
            priority=8,
        )
        developer = AIDecision(
            role=AIRole.DEVELOPER,
            recommendation="Test",
            confidence=0.9,
            reasoning="Developer analysis",
            priority=9,
        )
        lead = AIDecision(
            role=AIRole.LEAD,
            recommendation="Test",
            confidence=0.7,
            reasoning="Lead analysis",
            priority=7,
        )
        context = {"service_name": "test-service"}

        consensus = await orchestrator.compose_consensus(
            architect, developer, lead, context
        )

        assert isinstance(consensus, ConsensusDecision)
        assert len(consensus.contributing_decisions) == 3
        assert len(orchestrator.decision_history) == 1

    def test_confidence_to_priority(self, orchestrator):
        assert orchestrator._confidence_to_priority(0.0) == 1
        assert orchestrator._confidence_to_priority(0.5) == 5
        assert orchestrator._confidence_to_priority(1.0) == 10
        assert orchestrator._confidence_to_priority(1.5) == 10

    def test_suggest_tools(self, orchestrator):
        tools = orchestrator._suggest_tools(["injection", "xss"])
        assert "sqlmap" in tools or "burp" in tools

        tools = orchestrator._suggest_tools(["unknown_vector"])
        assert "burp" in tools or "manual" in tools

    def test_derive_strategy(self, orchestrator, mock_llm_manager):
        high_confidence = LLMResponse(
            recommended_action="test",
            confidence=0.9,
            reasoning="test",
        )
        assert "Aggressive" in orchestrator._derive_strategy(high_confidence)

        medium_high_confidence = LLMResponse(
            recommended_action="test",
            confidence=0.7,
            reasoning="test",
        )
        assert "Multi-stage" in orchestrator._derive_strategy(medium_high_confidence)

        medium_confidence = LLMResponse(
            recommended_action="test",
            confidence=0.5,
            reasoning="test",
        )
        assert "Conservative" in orchestrator._derive_strategy(medium_confidence)

        low_confidence = LLMResponse(
            recommended_action="test",
            confidence=0.3,
            reasoning="test",
        )
        assert "Manual" in orchestrator._derive_strategy(low_confidence)

    def test_derive_success_criteria(self, orchestrator, mock_llm_manager):
        response = LLMResponse(
            recommended_action="test",
            confidence=0.8,
            reasoning="test",
            mitre_techniques=["T1190"],
            compliance_concerns=["PCI-DSS"],
        )
        criteria = orchestrator._derive_success_criteria(response)

        assert "Vulnerability confirmed" in criteria
        assert "Evidence collected" in criteria
        assert "MITRE ATT&CK mapping verified" in criteria
        assert "Compliance impact documented" in criteria

    def test_assess_business_impact(self, orchestrator, mock_llm_manager):
        critical = LLMResponse(
            recommended_action="test",
            confidence=0.9,
            reasoning="test",
        )
        assert "Critical" in orchestrator._assess_business_impact(critical)

        high = LLMResponse(
            recommended_action="test",
            confidence=0.7,
            reasoning="test",
        )
        assert "High" in orchestrator._assess_business_impact(high)

        medium = LLMResponse(
            recommended_action="test",
            confidence=0.5,
            reasoning="test",
        )
        assert "Medium" in orchestrator._assess_business_impact(medium)

        low = LLMResponse(
            recommended_action="test",
            confidence=0.2,
            reasoning="test",
        )
        assert "Low" in orchestrator._assess_business_impact(low)

    def test_get_statistics(self, orchestrator):
        stats = orchestrator.get_statistics()

        assert "total_calls" in stats
        assert "successful_calls" in stats
        assert "fallback_calls" in stats
        assert "success_rate" in stats
        assert "decisions_made" in stats
        assert "config" in stats

    def test_fallback_decision(self, orchestrator):
        vulnerability = {"id": "CVE-2024-1234"}
        decision = orchestrator._fallback_decision(AIRole.ARCHITECT, vulnerability)

        assert decision.role == AIRole.ARCHITECT
        assert decision.confidence == 0.5
        assert decision.metadata.get("fallback") is True

    def test_fallback_consensus(self, orchestrator):
        architect = AIDecision(
            role=AIRole.ARCHITECT,
            recommendation="Test",
            confidence=0.6,
            reasoning="Test",
            priority=6,
        )
        developer = AIDecision(
            role=AIRole.DEVELOPER,
            recommendation="Test",
            confidence=0.7,
            reasoning="Test",
            priority=7,
        )
        lead = AIDecision(
            role=AIRole.LEAD,
            recommendation="Test",
            confidence=0.8,
            reasoning="Test",
            priority=8,
        )

        consensus = orchestrator._fallback_consensus(architect, developer, lead)

        assert consensus.action == "execute_pentest_with_caution"
        assert consensus.metadata.get("fallback") is True
        expected_confidence = (0.6 + 0.7 + 0.8) / 3
        assert abs(consensus.confidence - expected_confidence) < 0.01

    def test_fallback_consensus_with_contributing_fallbacks(self, orchestrator):
        """Test _fallback_consensus when contributing decisions are also fallbacks.

        This test exercises the code path that counts contributing fallback decisions
        and includes them in the consensus metadata and reasoning.
        """
        # Create decisions where some have fallback=True in metadata
        architect = AIDecision(
            role=AIRole.ARCHITECT,
            recommendation="Fallback recommendation",
            confidence=0.5,
            reasoning="Fallback reasoning",
            priority=5,
            metadata={"fallback": True},  # This is a fallback decision
        )
        developer = AIDecision(
            role=AIRole.DEVELOPER,
            recommendation="Real recommendation",
            confidence=0.7,
            reasoning="Real reasoning",
            priority=7,
            metadata={"fallback": False},  # This is NOT a fallback
        )
        lead = AIDecision(
            role=AIRole.LEAD,
            recommendation="Fallback recommendation",
            confidence=0.5,
            reasoning="Fallback reasoning",
            priority=5,
            metadata={"fallback": True},  # This is a fallback decision
        )

        consensus = orchestrator._fallback_consensus(architect, developer, lead)

        # Verify basic consensus properties
        assert consensus.action == "execute_pentest_with_caution"
        assert consensus.metadata.get("fallback") is True
        assert consensus.metadata.get("fallback_type") == "deterministic_consensus"
        assert consensus.metadata.get("fallback_reason") == "ai_composition_failed"
        assert consensus.metadata.get("ai_generated") is False
        assert consensus.metadata.get("requires_manual_review") is True
        assert (
            consensus.metadata.get("audit_label") == "FALLBACK_DETERMINISTIC_CONSENSUS"
        )

        # Verify contributing fallback count (2 out of 3 decisions are fallbacks)
        assert consensus.metadata.get("contributing_fallback_count") == 2

        # Verify reasoning mentions the fallback count
        assert "2/3 contributing decisions" in consensus.reasoning
        assert "DETERMINISTIC FALLBACK CONSENSUS" in consensus.reasoning
        assert "Manual review REQUIRED" in consensus.reasoning

        # Verify confidence is average of all three
        expected_confidence = (0.5 + 0.7 + 0.5) / 3
        assert abs(consensus.confidence - expected_confidence) < 0.01

        # Verify execution plan is present
        assert len(consensus.execution_plan) == 3
        assert consensus.execution_plan[0]["action"] == "Reconnaissance"

        # Verify fallback_timestamp is present
        assert "fallback_timestamp" in consensus.metadata


class TestLLMCallError:
    """Tests for LLMCallError exception."""

    def test_exception_message(self):
        error = LLMCallError("Test error message")
        assert str(error) == "Test error message"

    def test_exception_inheritance(self):
        error = LLMCallError("Test")
        assert isinstance(error, Exception)


class TestAIDecision:
    """Tests for AIDecision dataclass."""

    def test_creation(self):
        decision = AIDecision(
            role=AIRole.ARCHITECT,
            recommendation="Test recommendation",
            confidence=0.85,
            reasoning="Test reasoning",
            priority=8,
            metadata={"key": "value"},
        )

        assert decision.role == AIRole.ARCHITECT
        assert decision.recommendation == "Test recommendation"
        assert decision.confidence == 0.85
        assert decision.reasoning == "Test reasoning"
        assert decision.priority == 8
        assert decision.metadata == {"key": "value"}

    def test_default_metadata(self):
        decision = AIDecision(
            role=AIRole.DEVELOPER,
            recommendation="Test",
            confidence=0.5,
            reasoning="Test",
            priority=5,
        )
        assert decision.metadata == {}


class TestConsensusDecision:
    """Tests for ConsensusDecision dataclass."""

    def test_creation(self):
        decisions = [
            AIDecision(
                role=AIRole.ARCHITECT,
                recommendation="Test",
                confidence=0.8,
                reasoning="Test",
                priority=8,
            )
        ]

        consensus = ConsensusDecision(
            action="execute_pentest",
            confidence=0.85,
            reasoning="Consensus reached",
            contributing_decisions=decisions,
            execution_plan=[{"step": 1, "action": "test"}],
            metadata={"timestamp": "2024-01-01"},
        )

        assert consensus.action == "execute_pentest"
        assert consensus.confidence == 0.85
        assert len(consensus.contributing_decisions) == 1
        assert len(consensus.execution_plan) == 1


class TestAIRole:
    """Tests for AIRole enum."""

    def test_roles(self):
        assert AIRole.ARCHITECT.value == "architect"
        assert AIRole.DEVELOPER.value == "developer"
        assert AIRole.LEAD.value == "lead"
        assert AIRole.COMPOSER.value == "composer"
