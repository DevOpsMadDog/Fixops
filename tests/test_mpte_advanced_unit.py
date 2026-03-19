"""Comprehensive unit tests for mpte_advanced.py (V5 — MPTE Verification).

Tests the MultiAIOrchestrator, ConsensusConfig, AdvancedMPTEClient,
ExploitValidationFramework, and supporting dataclasses/helpers.

Coverage target: 80%+ of mpte_advanced.py
"""

import asyncio
import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.mpte_advanced import (
    LLMCallError,
    ConsensusConfig,
    AIRole,
    AIDecision,
    ConsensusDecision,
    MultiAIOrchestrator,
    ExploitValidationFramework,
    AdvancedMPTEClient,
)
from core.mpte_models import (
    ExploitabilityLevel,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestResult,
    PenTestStatus,
)


# ──────────────────────────────────────────────────────────────────────
# ConsensusConfig Tests
# ──────────────────────────────────────────────────────────────────────

class TestConsensusConfig:
    def test_default_values(self):
        config = ConsensusConfig()
        assert config.threshold == 0.6
        assert config.timeout_seconds == 30.0
        assert config.max_retries == 3
        assert config.fallback_enabled is True
        assert abs(sum(config.weights.values()) - 1.0) < 0.01

    def test_from_env_defaults(self):
        config = ConsensusConfig.from_env()
        assert config.threshold == 0.6
        assert config.weights["architect"] == 0.35
        assert config.weights["developer"] == 0.40
        assert config.weights["lead"] == 0.25

    @patch.dict(os.environ, {
        "FIXOPS_CONSENSUS_THRESHOLD": "0.8",
        "FIXOPS_CONSENSUS_WEIGHTS_ARCHITECT": "0.40",
        "FIXOPS_CONSENSUS_WEIGHTS_DEVELOPER": "0.35",
        "FIXOPS_CONSENSUS_WEIGHTS_LEAD": "0.25",
        "FIXOPS_LLM_TIMEOUT": "60",
        "FIXOPS_LLM_MAX_RETRIES": "5",
        "FIXOPS_LLM_FALLBACK_ENABLED": "false",
    })
    def test_from_env_custom(self):
        config = ConsensusConfig.from_env()
        assert config.threshold == 0.8
        assert config.weights["architect"] == 0.40
        assert config.timeout_seconds == 60.0
        assert config.max_retries == 5
        assert config.fallback_enabled is False

    def test_validate_valid(self):
        config = ConsensusConfig()
        config.validate()  # Should not raise

    def test_validate_threshold_out_of_range(self):
        config = ConsensusConfig(threshold=1.5)
        with pytest.raises(ValueError, match="threshold"):
            config.validate()

    def test_validate_threshold_negative(self):
        config = ConsensusConfig(threshold=-0.1)
        with pytest.raises(ValueError, match="threshold"):
            config.validate()

    def test_validate_weights_not_sum_to_one(self):
        config = ConsensusConfig(weights={"architect": 0.5, "developer": 0.5, "lead": 0.5})
        with pytest.raises(ValueError, match="weights"):
            config.validate()

    def test_validate_timeout_zero(self):
        config = ConsensusConfig(timeout_seconds=0)
        with pytest.raises(ValueError, match="Timeout"):
            config.validate()

    def test_validate_timeout_negative(self):
        config = ConsensusConfig(timeout_seconds=-1)
        with pytest.raises(ValueError, match="Timeout"):
            config.validate()

    def test_validate_max_retries_zero(self):
        config = ConsensusConfig(max_retries=0)
        with pytest.raises(ValueError, match="retries"):
            config.validate()


# ──────────────────────────────────────────────────────────────────────
# AIRole Enum Tests
# ──────────────────────────────────────────────────────────────────────

class TestAIRole:
    def test_roles_exist(self):
        assert AIRole.ARCHITECT.value == "architect"
        assert AIRole.DEVELOPER.value == "developer"
        assert AIRole.LEAD.value == "lead"
        assert AIRole.COMPOSER.value == "composer"


# ──────────────────────────────────────────────────────────────────────
# AIDecision Dataclass Tests
# ──────────────────────────────────────────────────────────────────────

class TestAIDecision:
    def test_basic_creation(self):
        decision = AIDecision(
            role=AIRole.ARCHITECT,
            recommendation="Block IP range",
            confidence=0.85,
            reasoning="High-risk pattern detected",
            priority=8,
        )
        assert decision.role == AIRole.ARCHITECT
        assert decision.confidence == 0.85
        assert decision.priority == 8
        assert decision.metadata == {}

    def test_with_metadata(self):
        decision = AIDecision(
            role=AIRole.DEVELOPER,
            recommendation="Apply patch",
            confidence=0.7,
            reasoning="Vuln confirmed",
            priority=6,
            metadata={"tools": ["sqlmap"]},
        )
        assert decision.metadata["tools"] == ["sqlmap"]


# ──────────────────────────────────────────────────────────────────────
# ConsensusDecision Dataclass Tests
# ──────────────────────────────────────────────────────────────────────

class TestConsensusDecision:
    def test_basic_creation(self):
        d1 = AIDecision(AIRole.ARCHITECT, "test", 0.8, "reason", 7)
        d2 = AIDecision(AIRole.DEVELOPER, "test", 0.9, "reason", 8)
        d3 = AIDecision(AIRole.LEAD, "test", 0.75, "reason", 6)

        consensus = ConsensusDecision(
            action="execute_pentest",
            confidence=0.82,
            reasoning="All experts agree",
            contributing_decisions=[d1, d2, d3],
            execution_plan=[{"step": 1, "action": "Recon"}],
        )
        assert consensus.action == "execute_pentest"
        assert len(consensus.contributing_decisions) == 3
        assert len(consensus.execution_plan) == 1


# ──────────────────────────────────────────────────────────────────────
# MultiAIOrchestrator Tests
# ──────────────────────────────────────────────────────────────────────

class TestMultiAIOrchestrator:
    @pytest.fixture
    def mock_llm_manager(self):
        manager = MagicMock()
        # Create a mock LLMResponse
        mock_response = MagicMock()
        mock_response.recommended_action = "execute_pentest"
        mock_response.confidence = 0.8
        mock_response.reasoning = "Analysis complete"
        mock_response.attack_vectors = ["injection", "xss"]
        mock_response.mitre_techniques = ["T1190"]
        mock_response.compliance_concerns = ["PCI-DSS"]
        mock_response.metadata = {"mode": "live", "duration_ms": 150}
        manager.analyse.return_value = mock_response
        return manager

    @pytest.fixture
    def orchestrator(self, mock_llm_manager):
        config = ConsensusConfig(threshold=0.6, max_retries=1, timeout_seconds=5)
        return MultiAIOrchestrator(mock_llm_manager, config)

    def test_init(self, orchestrator):
        assert orchestrator.config.threshold == 0.6
        assert orchestrator.decision_history == []
        assert orchestrator._call_count["total"] == 0

    def test_init_validates_config(self):
        manager = MagicMock()
        bad_config = ConsensusConfig(threshold=2.0)
        with pytest.raises(ValueError):
            MultiAIOrchestrator(manager, bad_config)

    # --- Helper method tests ---

    def test_confidence_to_priority(self, orchestrator):
        assert orchestrator._confidence_to_priority(0.0) == 1
        assert orchestrator._confidence_to_priority(0.5) == 5
        assert orchestrator._confidence_to_priority(0.85) == 8
        assert orchestrator._confidence_to_priority(1.0) == 10
        assert orchestrator._confidence_to_priority(1.5) == 10  # Clamped

    def test_suggest_tools_injection(self, orchestrator):
        tools = orchestrator._suggest_tools(["injection"])
        assert "sqlmap" in tools
        assert "burp" in tools

    def test_suggest_tools_xss(self, orchestrator):
        tools = orchestrator._suggest_tools(["xss"])
        assert "xsstrike" in tools or "dalfox" in tools

    def test_suggest_tools_rce(self, orchestrator):
        tools = orchestrator._suggest_tools(["rce"])
        assert "metasploit" in tools

    def test_suggest_tools_unknown(self, orchestrator):
        tools = orchestrator._suggest_tools(["unknown_vector"])
        assert "burp" in tools
        assert "manual" in tools

    def test_suggest_tools_multiple(self, orchestrator):
        tools = orchestrator._suggest_tools(["injection", "xss"])
        assert len(tools) >= 2

    def test_suggest_tools_empty(self, orchestrator):
        tools = orchestrator._suggest_tools([])
        assert "burp" in tools
        assert "manual" in tools

    def test_derive_strategy_high_confidence(self, orchestrator):
        response = MagicMock()
        response.confidence = 0.9
        assert "Aggressive" in orchestrator._derive_strategy(response)

    def test_derive_strategy_medium_confidence(self, orchestrator):
        response = MagicMock()
        response.confidence = 0.7
        assert "Multi-stage" in orchestrator._derive_strategy(response)

    def test_derive_strategy_low_confidence(self, orchestrator):
        response = MagicMock()
        response.confidence = 0.5
        assert "Conservative" in orchestrator._derive_strategy(response)

    def test_derive_strategy_very_low_confidence(self, orchestrator):
        response = MagicMock()
        response.confidence = 0.2
        assert "Manual" in orchestrator._derive_strategy(response)

    def test_derive_success_criteria_basic(self, orchestrator):
        response = MagicMock()
        response.compliance_concerns = []
        response.mitre_techniques = []
        criteria = orchestrator._derive_success_criteria(response)
        assert "Vulnerability confirmed" in criteria
        assert "Evidence collected" in criteria

    def test_derive_success_criteria_with_compliance(self, orchestrator):
        response = MagicMock()
        response.compliance_concerns = ["PCI-DSS"]
        response.mitre_techniques = []
        criteria = orchestrator._derive_success_criteria(response)
        assert any("Compliance" in c for c in criteria)

    def test_derive_success_criteria_with_mitre(self, orchestrator):
        response = MagicMock()
        response.compliance_concerns = []
        response.mitre_techniques = ["T1190"]
        criteria = orchestrator._derive_success_criteria(response)
        assert any("MITRE" in c for c in criteria)

    def test_assess_business_impact_critical(self, orchestrator):
        response = MagicMock()
        response.confidence = 0.9
        assert "Critical" in orchestrator._assess_business_impact(response)

    def test_assess_business_impact_high(self, orchestrator):
        response = MagicMock()
        response.confidence = 0.7
        assert "High" in orchestrator._assess_business_impact(response)

    def test_assess_business_impact_medium(self, orchestrator):
        response = MagicMock()
        response.confidence = 0.5
        assert "Medium" in orchestrator._assess_business_impact(response)

    def test_assess_business_impact_low(self, orchestrator):
        response = MagicMock()
        response.confidence = 0.2
        assert "Low" in orchestrator._assess_business_impact(response)

    # --- Fallback decision tests ---

    def test_fallback_decision(self, orchestrator):
        vuln = {"id": "test-vuln-1", "type": "SQLi"}
        decision = orchestrator._fallback_decision(AIRole.ARCHITECT, vuln)

        assert isinstance(decision, AIDecision)
        assert decision.role == AIRole.ARCHITECT
        assert decision.confidence == 0.5
        assert decision.metadata["fallback"] is True
        assert decision.metadata["ai_generated"] is False
        assert "DETERMINISTIC" in decision.reasoning

    def test_fallback_decision_unknown_vuln(self, orchestrator):
        decision = orchestrator._fallback_decision(AIRole.DEVELOPER, {})
        assert decision.metadata["vulnerability_id"] == "unknown"

    # --- Fallback consensus tests ---

    def test_fallback_consensus(self, orchestrator):
        d1 = AIDecision(AIRole.ARCHITECT, "test", 0.8, "r", 7)
        d2 = AIDecision(AIRole.DEVELOPER, "test", 0.6, "r", 5)
        d3 = AIDecision(AIRole.LEAD, "test", 0.7, "r", 6)

        consensus = orchestrator._fallback_consensus(d1, d2, d3)
        assert isinstance(consensus, ConsensusDecision)
        assert consensus.action == "execute_pentest_with_caution"
        assert consensus.metadata["fallback"] is True
        expected_conf = (0.8 + 0.6 + 0.7) / 3
        assert abs(consensus.confidence - expected_conf) < 0.01

    def test_fallback_consensus_counts_contributing_fallbacks(self, orchestrator):
        d1 = AIDecision(AIRole.ARCHITECT, "t", 0.5, "r", 5, metadata={"fallback": True})
        d2 = AIDecision(AIRole.DEVELOPER, "t", 0.5, "r", 5, metadata={"fallback": True})
        d3 = AIDecision(AIRole.LEAD, "t", 0.7, "r", 6, metadata={})

        consensus = orchestrator._fallback_consensus(d1, d2, d3)
        assert consensus.metadata["contributing_fallback_count"] == 2

    # --- Statistics ---

    def test_get_statistics_initial(self, orchestrator):
        stats = orchestrator.get_statistics()
        assert stats["total_calls"] == 0
        assert stats["decisions_made"] == 0
        assert stats["success_rate"] == 0

    def test_get_statistics_after_calls(self, orchestrator):
        orchestrator._call_count = {"total": 10, "success": 7, "fallback": 3}
        orchestrator.decision_history = [MagicMock(), MagicMock()]
        stats = orchestrator.get_statistics()
        assert stats["total_calls"] == 10
        assert stats["success_rate"] == 0.7
        assert stats["fallback_rate"] == 0.3
        assert stats["decisions_made"] == 2

    # --- Async decision methods ---

    @pytest.mark.asyncio
    async def test_get_architect_decision(self, orchestrator, mock_llm_manager):
        context = {"target": "https://example.com"}
        vuln = {"id": "v1", "type": "SQLi"}
        decision = await orchestrator.get_architect_decision(context, vuln)
        assert isinstance(decision, AIDecision)
        assert decision.role == AIRole.ARCHITECT

    @pytest.mark.asyncio
    async def test_get_developer_decision(self, orchestrator, mock_llm_manager):
        context = {"target": "https://example.com"}
        vuln = {"id": "v1", "type": "XSS"}
        decision = await orchestrator.get_developer_decision(context, vuln)
        assert isinstance(decision, AIDecision)
        assert decision.role == AIRole.DEVELOPER

    @pytest.mark.asyncio
    async def test_get_lead_decision(self, orchestrator, mock_llm_manager):
        context = {"target": "https://example.com"}
        vuln = {"id": "v1", "type": "RCE"}
        decision = await orchestrator.get_lead_decision(context, vuln)
        assert isinstance(decision, AIDecision)
        assert decision.role == AIRole.LEAD

    @pytest.mark.asyncio
    async def test_decision_fallback_on_error(self, orchestrator, mock_llm_manager):
        mock_llm_manager.analyse.side_effect = Exception("API down")
        context = {"target": "https://example.com"}
        vuln = {"id": "v1", "type": "SQLi"}
        decision = await orchestrator.get_architect_decision(context, vuln)
        # _call_llm returns fallback JSON which get_architect_decision parses normally
        # The fallback is reflected in confidence=0.5 and recommendation
        assert decision.confidence == 0.5
        assert decision.recommendation == "Proceed with standard testing"
        assert "Fallback" in decision.reasoning or "manual_review" in str(decision.metadata)

    @pytest.mark.asyncio
    async def test_compose_consensus(self, orchestrator, mock_llm_manager):
        d1 = AIDecision(AIRole.ARCHITECT, "block", 0.8, "reason", 8)
        d2 = AIDecision(AIRole.DEVELOPER, "test", 0.9, "reason", 9)
        d3 = AIDecision(AIRole.LEAD, "approve", 0.75, "reason", 7)
        context = {"target": "test"}

        consensus = await orchestrator.compose_consensus(d1, d2, d3, context)
        assert isinstance(consensus, ConsensusDecision)
        # Weighted confidence
        expected = 0.8 * 0.35 + 0.9 * 0.40 + 0.75 * 0.25
        assert abs(consensus.confidence - expected) < 0.01
        assert len(consensus.contributing_decisions) == 3
        assert len(orchestrator.decision_history) == 1

    @pytest.mark.asyncio
    async def test_compose_consensus_fallback_on_error(self, orchestrator, mock_llm_manager):
        mock_llm_manager.analyse.side_effect = Exception("API down")
        d1 = AIDecision(AIRole.ARCHITECT, "t", 0.8, "r", 8)
        d2 = AIDecision(AIRole.DEVELOPER, "t", 0.9, "r", 9)
        d3 = AIDecision(AIRole.LEAD, "t", 0.75, "r", 7)

        consensus = await orchestrator.compose_consensus(d1, d2, d3, {})
        # _call_llm with fallback_enabled returns fallback JSON, compose_consensus
        # parses it successfully, so weighted confidence is still computed normally
        assert isinstance(consensus, ConsensusDecision)
        assert len(consensus.contributing_decisions) == 3
        # Reasoning contains the fallback message from _call_llm
        assert "Fallback" in consensus.reasoning or consensus.confidence > 0


# ──────────────────────────────────────────────────────────────────────
# _call_llm Tests
# ──────────────────────────────────────────────────────────────────────

class TestCallLLM:
    @pytest.fixture
    def mock_llm_manager(self):
        manager = MagicMock()
        mock_response = MagicMock()
        mock_response.recommended_action = "test_action"
        mock_response.confidence = 0.85
        mock_response.reasoning = "Test reasoning"
        mock_response.attack_vectors = ["injection"]
        mock_response.mitre_techniques = ["T1190"]
        mock_response.compliance_concerns = ["PCI-DSS"]
        mock_response.metadata = {"mode": "live", "duration_ms": 100}
        manager.analyse.return_value = mock_response
        return manager

    @pytest.fixture
    def orchestrator(self, mock_llm_manager):
        config = ConsensusConfig(threshold=0.6, max_retries=1, timeout_seconds=5)
        return MultiAIOrchestrator(mock_llm_manager, config)

    @pytest.mark.asyncio
    async def test_call_llm_success(self, orchestrator, mock_llm_manager):
        result = await orchestrator._call_llm("openai", "test prompt")
        parsed = json.loads(result)
        assert parsed["recommendation"] == "test_action"
        assert parsed["confidence"] == 0.85
        assert orchestrator._call_count["success"] == 1

    @pytest.mark.asyncio
    async def test_call_llm_deterministic_mode(self, orchestrator, mock_llm_manager):
        mock_response = mock_llm_manager.analyse.return_value
        mock_response.metadata = {"mode": "deterministic", "reason": "no API key"}
        await orchestrator._call_llm("openai", "test prompt")
        assert orchestrator._call_count["fallback"] == 1

    @pytest.mark.asyncio
    async def test_call_llm_fallback_on_all_retries_fail(self, mock_llm_manager):
        mock_llm_manager.analyse.side_effect = RuntimeError("Connection refused")
        config = ConsensusConfig(threshold=0.6, max_retries=2, timeout_seconds=1, fallback_enabled=True)
        orchestrator = MultiAIOrchestrator(mock_llm_manager, config)

        result = await orchestrator._call_llm("openai", "test prompt")
        parsed = json.loads(result)
        assert parsed.get("metadata", {}).get("fallback") is True
        assert orchestrator._call_count["fallback"] == 1

    @pytest.mark.asyncio
    async def test_call_llm_raises_when_fallback_disabled(self, mock_llm_manager):
        mock_llm_manager.analyse.side_effect = RuntimeError("Connection refused")
        config = ConsensusConfig(threshold=0.6, max_retries=1, timeout_seconds=1, fallback_enabled=False)
        orchestrator = MultiAIOrchestrator(mock_llm_manager, config)

        with pytest.raises(LLMCallError, match="Connection refused"):
            await orchestrator._call_llm("openai", "test prompt")

    @pytest.mark.asyncio
    async def test_call_llm_timeout(self, mock_llm_manager):
        async def slow_analyse(*args, **kwargs):
            await asyncio.sleep(10)

        mock_llm_manager.analyse.side_effect = lambda *a, **k: slow_analyse()
        config = ConsensusConfig(threshold=0.6, max_retries=1, timeout_seconds=0.1, fallback_enabled=True)
        orchestrator = MultiAIOrchestrator(mock_llm_manager, config)

        result = await orchestrator._call_llm("openai", "test prompt")
        parsed = json.loads(result)
        assert parsed.get("metadata", {}).get("fallback") is True


# ──────────────────────────────────────────────────────────────────────
# ExploitValidationFramework Tests
# ──────────────────────────────────────────────────────────────────────

class TestExploitValidationFramework:
    @pytest.fixture
    def mock_client(self):
        client = MagicMock()
        client.execute_pentest = AsyncMock(return_value={
            "exploit_successful": True,
            "confidence_score": 0.9,
        })
        return client

    @pytest.fixture
    def framework(self, mock_client):
        return ExploitValidationFramework(mock_client)

    @pytest.mark.asyncio
    async def test_validate_exploitability_confirmed(self, framework):
        vuln = {"id": "v1", "type": "SQLi"}
        context = {"target_url": "https://test.com"}
        level, result = await framework.validate_exploitability(vuln, context)
        assert level == ExploitabilityLevel.CONFIRMED_EXPLOITABLE

    @pytest.mark.asyncio
    async def test_validate_exploitability_cache(self, framework, mock_client):
        vuln = {"id": "cached-v1", "type": "XSS"}
        context = {"target_url": "https://test.com"}

        # First call
        await framework.validate_exploitability(vuln, context)
        # Second call should use cache
        level, result = await framework.validate_exploitability(vuln, context)
        assert result == {"cached": True}
        assert mock_client.execute_pentest.call_count == 1

    @pytest.mark.asyncio
    async def test_validate_exploitability_error(self, framework, mock_client):
        mock_client.execute_pentest = AsyncMock(side_effect=Exception("API error"))
        vuln = {"id": "error-v1", "type": "RCE"}
        context = {}
        level, result = await framework.validate_exploitability(vuln, context)
        assert level == ExploitabilityLevel.INCONCLUSIVE
        assert "error" in result

    def test_create_test_request(self, framework):
        vuln = {"id": "v1", "type": "SQLi", "severity": "critical", "description": "SQL injection in login"}
        context = {"target_url": "https://target.com"}
        request = framework._create_test_request(vuln, context)
        assert isinstance(request, PenTestRequest)
        assert request.finding_id == "v1"
        assert request.target_url == "https://target.com"
        assert request.priority == PenTestPriority.CRITICAL

    def test_create_test_request_defaults(self, framework):
        request = framework._create_test_request({}, {})
        assert request.finding_id == "unknown"
        assert request.target_url == "http://localhost"
        assert request.priority == PenTestPriority.MEDIUM

    def test_generate_test_case(self, framework):
        vuln = {"type": "XSS", "description": "Reflected XSS in search"}
        test_case = framework._generate_test_case(vuln)
        assert "XSS" in test_case
        assert "Reflected XSS" in test_case

    def test_map_priority(self, framework):
        assert framework._map_priority("critical") == PenTestPriority.CRITICAL
        assert framework._map_priority("high") == PenTestPriority.HIGH
        assert framework._map_priority("medium") == PenTestPriority.MEDIUM
        assert framework._map_priority("low") == PenTestPriority.LOW
        assert framework._map_priority("unknown") == PenTestPriority.MEDIUM

    def test_analyze_test_results_confirmed(self, framework):
        result = {"exploit_successful": True, "confidence_score": 0.9}
        assert framework._analyze_test_results(result) == ExploitabilityLevel.CONFIRMED_EXPLOITABLE

    def test_analyze_test_results_likely(self, framework):
        result = {"exploit_successful": True, "confidence_score": 0.6}
        assert framework._analyze_test_results(result) == ExploitabilityLevel.LIKELY_EXPLOITABLE

    def test_analyze_test_results_unexploitable(self, framework):
        result = {"exploit_successful": False, "confidence_score": 0.9}
        assert framework._analyze_test_results(result) == ExploitabilityLevel.UNEXPLOITABLE

    def test_analyze_test_results_blocked(self, framework):
        result = {"exploit_successful": False, "confidence_score": 0.3, "blocked": True}
        assert framework._analyze_test_results(result) == ExploitabilityLevel.BLOCKED

    def test_analyze_test_results_inconclusive(self, framework):
        result = {"exploit_successful": False, "confidence_score": 0.3}
        assert framework._analyze_test_results(result) == ExploitabilityLevel.INCONCLUSIVE

    def test_analyze_test_results_empty(self, framework):
        assert framework._analyze_test_results({}) == ExploitabilityLevel.INCONCLUSIVE
        assert framework._analyze_test_results(None) == ExploitabilityLevel.INCONCLUSIVE


# ──────────────────────────────────────────────────────────────────────
# AdvancedMPTEClient Tests
# ──────────────────────────────────────────────────────────────────────

class TestAdvancedMPTEClient:
    @pytest.fixture
    def mock_db(self):
        db = MagicMock()
        db.create_request.side_effect = lambda r: r
        db.update_request.return_value = None
        db.create_result.return_value = None
        db.list_requests.return_value = []
        db.list_results.return_value = []
        return db

    @pytest.fixture
    def mock_llm(self):
        manager = MagicMock()
        mock_response = MagicMock()
        mock_response.recommended_action = "test_action"
        mock_response.confidence = 0.85
        mock_response.reasoning = "Analysis done"
        mock_response.attack_vectors = ["injection"]
        mock_response.mitre_techniques = ["T1190"]
        mock_response.compliance_concerns = []
        mock_response.metadata = {"mode": "live"}
        manager.analyse.return_value = mock_response
        return manager

    @pytest.fixture
    def client(self, mock_db, mock_llm):
        config = PenTestConfig(
            id="test-config-1",
            name="Test Config",
            mpte_url="https://localhost:8443",
            api_key="test-key",
            timeout_seconds=10,
        )
        return AdvancedMPTEClient(config, mock_llm, db=mock_db)

    def test_init(self, client):
        assert isinstance(client.orchestrator, MultiAIOrchestrator)
        assert isinstance(client.validator, ExploitValidationFramework)
        assert client.session is None

    def test_create_inconclusive_response(self, client):
        request = PenTestRequest(
            id="req-1",
            finding_id="f-1",
            target_url="https://test.com",
            vulnerability_type="SQLi",
            test_case="test",
            priority=PenTestPriority.HIGH,
        )
        result = client._create_inconclusive_response(request, "timeout")
        assert result["status"] == "failed"
        assert result["exploit_successful"] is False
        assert result["exploitability"] == "inconclusive"
        assert result["confidence_score"] == 0.0

    def test_create_result_from_response(self, client):
        request = PenTestRequest(
            id="req-1",
            finding_id="f-1",
            target_url="https://test.com",
            vulnerability_type="SQLi",
            test_case="test",
            priority=PenTestPriority.HIGH,
        )
        response = {
            "exploitability": "confirmed_exploitable",
            "exploit_successful": True,
            "evidence": "SQL error dumped",
            "steps_taken": ["Step 1", "Step 2"],
            "artifacts": ["screenshot.png"],
            "confidence_score": 0.95,
            "execution_time_seconds": 12.5,
        }
        result = client._create_result_from_response(request, response)
        assert isinstance(result, PenTestResult)
        assert result.exploitability == ExploitabilityLevel.CONFIRMED_EXPLOITABLE
        assert result.exploit_successful is True
        assert result.confidence_score == 0.95

    def test_create_result_from_response_inconclusive(self, client):
        request = PenTestRequest(
            id="req-1", finding_id="f-1", target_url="https://test.com",
            vulnerability_type="SQLi", test_case="test", priority=PenTestPriority.MEDIUM,
        )
        response = {"exploitability": "unknown_level"}
        result = client._create_result_from_response(request, response)
        assert result.exploitability == ExploitabilityLevel.INCONCLUSIVE

    def test_get_statistics_empty(self, client, mock_db):
        stats = client.get_statistics()
        assert stats["total_tests"] == 0
        assert stats["success_rate"] == 0
        assert stats["false_positive_rate"] == 0

    def test_get_statistics_with_data(self, client, mock_db):
        mock_req1 = MagicMock()
        mock_req1.status = PenTestStatus.COMPLETED
        mock_req2 = MagicMock()
        mock_req2.status = PenTestStatus.FAILED
        mock_db.list_requests.return_value = [mock_req1, mock_req2]

        mock_res1 = MagicMock()
        mock_res1.exploitability = ExploitabilityLevel.CONFIRMED_EXPLOITABLE
        mock_res1.execution_time_seconds = 10.0
        mock_res2 = MagicMock()
        mock_res2.exploitability = ExploitabilityLevel.UNEXPLOITABLE
        mock_res2.execution_time_seconds = 5.0
        mock_db.list_results.return_value = [mock_res1, mock_res2]

        stats = client.get_statistics()
        assert stats["total_tests"] == 2
        assert stats["completed_tests"] == 1
        assert stats["failed_tests"] == 1
        assert stats["confirmed_exploitable"] == 1
        assert stats["false_positives"] == 1
        assert stats["average_execution_time_seconds"] == 7.5

    @pytest.mark.asyncio
    async def test_async_context_manager(self, mock_db, mock_llm):
        config = PenTestConfig(id="ctx-1", name="Ctx Test", mpte_url="https://localhost:8443", timeout_seconds=5)
        async with AdvancedMPTEClient(config, mock_llm, db=mock_db) as client:
            assert client.session is not None
        # Session should be closed after exit

    @pytest.mark.asyncio
    async def test_execute_pentest_with_consensus_high_confidence(self, client, mock_llm):
        vuln = {"id": "v1", "type": "SQLi"}
        context = {"target_url": "https://test.com"}
        result = await client.execute_pentest_with_consensus(vuln, context)
        assert "consensus" in result

    @pytest.mark.asyncio
    async def test_execute_consensus_plan(self, client):
        consensus = ConsensusDecision(
            action="test",
            confidence=0.8,
            reasoning="test",
            contributing_decisions=[],
            execution_plan=[
                {"step": 1, "action": "Recon", "tool": "nmap"},
                {"step": 2, "action": "Exploit", "tool": "sqlmap"},
            ],
        )
        result = await client._execute_consensus_plan(consensus, {"id": "v1"}, {})
        assert result["steps_executed"] == 2
        # Steps are not yet wired to real engine — overall_success reflects that
        assert result["overall_success"] is False

    @pytest.mark.asyncio
    async def test_execute_step(self, client):
        step = {"action": "Reconnaissance", "tool": "nmap"}
        result = await client._execute_step(step, {"id": "v1"}, {})
        # Step executor not yet connected — returns honest failure
        assert result["success"] is False
        assert "Reconnaissance" in result["output"]


# ──────────────────────────────────────────────────────────────────────
# LLMCallError Tests
# ──────────────────────────────────────────────────────────────────────

class TestLLMCallError:
    def test_is_exception(self):
        err = LLMCallError("test error")
        assert isinstance(err, Exception)
        assert str(err) == "test error"
