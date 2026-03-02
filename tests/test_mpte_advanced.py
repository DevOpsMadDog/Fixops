"""Comprehensive tests for suite-core/core/mpte_advanced.py (1089 LOC).

Tests cover:
- ConsensusConfig: defaults, from_env(), validate() boundary conditions
- AIRole enum: all values
- AIDecision / ConsensusDecision dataclasses
- MultiAIOrchestrator: LLM calls, fallback, consensus, helper methods, statistics
- ExploitValidationFramework: validation, caching, test request creation, result analysis
- AdvancedMPTEClient: context manager, pentest execution, remediation validation, statistics

All LLM providers, aiohttp sessions, and MPTEDB are mocked. No real API calls.
"""

import asyncio
import json
import os
from dataclasses import fields as dc_fields
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from core.mpte_advanced import (
    AIDecision,
    AIRole,
    AdvancedMPTEClient,
    ConsensusConfig,
    ConsensusDecision,
    ExploitValidationFramework,
    LLMCallError,
    MultiAIOrchestrator,
)
from core.llm_providers import LLMResponse
from core.mpte_models import (
    ExploitabilityLevel,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestResult,
    PenTestStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SENTINEL = object()


def _make_llm_response(
    action: str = "execute_pentest",
    confidence: float = 0.85,
    reasoning: str = "Test reasoning",
    mitre: Any = _SENTINEL,
    compliance: Any = _SENTINEL,
    attack_vectors: Any = _SENTINEL,
    metadata: Any = _SENTINEL,
) -> LLMResponse:
    """Create a realistic LLMResponse for testing."""
    return LLMResponse(
        recommended_action=action,
        confidence=confidence,
        reasoning=reasoning,
        mitre_techniques=["T1190", "T1059"] if mitre is _SENTINEL else mitre,
        compliance_concerns=["PCI-DSS", "SOC2"] if compliance is _SENTINEL else compliance,
        attack_vectors=["injection", "authentication_bypass"] if attack_vectors is _SENTINEL else attack_vectors,
        metadata={"mode": "live", "duration_ms": 150} if metadata is _SENTINEL else metadata,
    )


def _make_mock_llm_manager(
    response: Optional[LLMResponse] = None,
    side_effect: Optional[Exception] = None,
) -> MagicMock:
    """Create a mock LLMProviderManager."""
    mgr = MagicMock()
    if side_effect:
        mgr.analyse.side_effect = side_effect
    else:
        mgr.analyse.return_value = response or _make_llm_response()
    return mgr


def _make_mock_db() -> MagicMock:
    """Create a mock MPTEDB."""
    db = MagicMock()
    db.create_request.side_effect = lambda r: _assign_id(r)
    db.update_request.side_effect = lambda r: r
    db.create_result.side_effect = lambda r: _assign_id(r)
    db.list_requests.return_value = []
    db.list_results.return_value = []
    return db


def _assign_id(obj):
    """Assign a UUID if missing (mimics MPTEDB behavior)."""
    if not obj.id:
        obj.id = "test-uuid-1234"
    return obj


def _default_config() -> ConsensusConfig:
    """Default valid config."""
    return ConsensusConfig(
        threshold=0.6,
        weights={"architect": 0.35, "developer": 0.40, "lead": 0.25},
        timeout_seconds=30.0,
        max_retries=3,
        fallback_enabled=True,
    )


def _make_pentest_config() -> PenTestConfig:
    """Create a PenTestConfig for testing."""
    return PenTestConfig(
        id="cfg-1",
        name="test-config",
        mpte_url="https://mpte.example.com",
        api_key="test-key",
        timeout_seconds=60,
    )


def _make_vulnerability(
    vuln_id: str = "CVE-2024-1234",
    vuln_type: str = "SQL Injection",
    severity: str = "high",
    description: str = "SQL injection in login form",
) -> Dict:
    return {
        "id": vuln_id,
        "type": vuln_type,
        "severity": severity,
        "description": description,
    }


def _make_context(target_url: str = "https://target.example.com") -> Dict:
    return {"target_url": target_url, "app_name": "TestApp", "env": "staging"}


def _make_orchestrator(
    llm_response: Optional[LLMResponse] = None,
    llm_side_effect: Optional[Exception] = None,
    config: Optional[ConsensusConfig] = None,
) -> MultiAIOrchestrator:
    mgr = _make_mock_llm_manager(llm_response, llm_side_effect)
    return MultiAIOrchestrator(mgr, config or _default_config())


# =========================================================================
# 1. ConsensusConfig tests
# =========================================================================

class TestConsensusConfig:
    """Tests for ConsensusConfig dataclass."""

    def test_default_values(self):
        cfg = ConsensusConfig()
        assert cfg.threshold == 0.6
        assert cfg.weights == {"architect": 0.35, "developer": 0.40, "lead": 0.25}
        assert cfg.timeout_seconds == 30.0
        assert cfg.max_retries == 3
        assert cfg.fallback_enabled is True

    def test_custom_values(self):
        cfg = ConsensusConfig(threshold=0.9, timeout_seconds=60, max_retries=5)
        assert cfg.threshold == 0.9
        assert cfg.timeout_seconds == 60
        assert cfg.max_retries == 5

    @patch.dict(os.environ, {
        "FIXOPS_CONSENSUS_THRESHOLD": "0.8",
        "FIXOPS_CONSENSUS_WEIGHTS_ARCHITECT": "0.30",
        "FIXOPS_CONSENSUS_WEIGHTS_DEVELOPER": "0.50",
        "FIXOPS_CONSENSUS_WEIGHTS_LEAD": "0.20",
        "FIXOPS_LLM_TIMEOUT": "45",
        "FIXOPS_LLM_MAX_RETRIES": "5",
        "FIXOPS_LLM_FALLBACK_ENABLED": "false",
    })
    def test_from_env_all_set(self):
        cfg = ConsensusConfig.from_env()
        assert cfg.threshold == 0.8
        assert cfg.weights["architect"] == 0.30
        assert cfg.weights["developer"] == 0.50
        assert cfg.weights["lead"] == 0.20
        assert cfg.timeout_seconds == 45.0
        assert cfg.max_retries == 5
        assert cfg.fallback_enabled is False

    @patch.dict(os.environ, {}, clear=True)
    def test_from_env_defaults(self):
        cfg = ConsensusConfig.from_env()
        assert cfg.threshold == 0.6
        assert cfg.weights["architect"] == 0.35
        assert cfg.timeout_seconds == 30.0
        assert cfg.max_retries == 3
        assert cfg.fallback_enabled is True

    @patch.dict(os.environ, {"FIXOPS_LLM_FALLBACK_ENABLED": "1"})
    def test_from_env_fallback_truthy_1(self):
        cfg = ConsensusConfig.from_env()
        assert cfg.fallback_enabled is True

    @patch.dict(os.environ, {"FIXOPS_LLM_FALLBACK_ENABLED": "yes"})
    def test_from_env_fallback_truthy_yes(self):
        cfg = ConsensusConfig.from_env()
        assert cfg.fallback_enabled is True

    @patch.dict(os.environ, {"FIXOPS_LLM_FALLBACK_ENABLED": "no"})
    def test_from_env_fallback_falsy(self):
        cfg = ConsensusConfig.from_env()
        assert cfg.fallback_enabled is False

    @patch.dict(os.environ, {"FIXOPS_LLM_FALLBACK_ENABLED": "TRUE"})
    def test_from_env_fallback_case_insensitive(self):
        cfg = ConsensusConfig.from_env()
        assert cfg.fallback_enabled is True

    def test_validate_valid_config(self):
        cfg = _default_config()
        cfg.validate()  # Should not raise

    def test_validate_threshold_zero(self):
        cfg = ConsensusConfig(threshold=0.0)
        cfg.validate()  # 0.0 is valid boundary

    def test_validate_threshold_one(self):
        cfg = ConsensusConfig(threshold=1.0)
        cfg.validate()  # 1.0 is valid boundary

    def test_validate_threshold_negative(self):
        cfg = ConsensusConfig(threshold=-0.1)
        with pytest.raises(ValueError, match="between 0 and 1"):
            cfg.validate()

    def test_validate_threshold_above_one(self):
        cfg = ConsensusConfig(threshold=1.1)
        with pytest.raises(ValueError, match="between 0 and 1"):
            cfg.validate()

    def test_validate_weights_must_sum_to_one(self):
        cfg = ConsensusConfig(weights={"a": 0.5, "b": 0.3})
        with pytest.raises(ValueError, match="must sum to 1.0"):
            cfg.validate()

    def test_validate_weights_tolerance(self):
        # Within 0.01 tolerance
        cfg = ConsensusConfig(weights={"a": 0.35, "b": 0.40, "c": 0.255})
        cfg.validate()  # sum=1.005, within 0.01

    def test_validate_weights_just_outside_tolerance(self):
        cfg = ConsensusConfig(weights={"a": 0.35, "b": 0.40, "c": 0.24})
        with pytest.raises(ValueError, match="must sum to 1.0"):
            cfg.validate()

    def test_validate_timeout_zero(self):
        cfg = ConsensusConfig(timeout_seconds=0)
        with pytest.raises(ValueError, match="Timeout must be positive"):
            cfg.validate()

    def test_validate_timeout_negative(self):
        cfg = ConsensusConfig(timeout_seconds=-5)
        with pytest.raises(ValueError, match="Timeout must be positive"):
            cfg.validate()

    def test_validate_max_retries_zero(self):
        cfg = ConsensusConfig(max_retries=0)
        with pytest.raises(ValueError, match="at least 1"):
            cfg.validate()

    def test_validate_max_retries_negative(self):
        cfg = ConsensusConfig(max_retries=-1)
        with pytest.raises(ValueError, match="at least 1"):
            cfg.validate()

    def test_validate_max_retries_one(self):
        cfg = ConsensusConfig(max_retries=1)
        cfg.validate()  # Should not raise


# =========================================================================
# 2. AIRole enum tests
# =========================================================================

class TestAIRole:
    """Tests for AIRole enum."""

    def test_architect_value(self):
        assert AIRole.ARCHITECT.value == "architect"

    def test_developer_value(self):
        assert AIRole.DEVELOPER.value == "developer"

    def test_lead_value(self):
        assert AIRole.LEAD.value == "lead"

    def test_composer_value(self):
        assert AIRole.COMPOSER.value == "composer"

    def test_all_members(self):
        assert len(AIRole) == 4

    def test_from_string(self):
        assert AIRole("architect") == AIRole.ARCHITECT
        assert AIRole("developer") == AIRole.DEVELOPER
        assert AIRole("lead") == AIRole.LEAD
        assert AIRole("composer") == AIRole.COMPOSER


# =========================================================================
# 3. AIDecision dataclass tests
# =========================================================================

class TestAIDecision:
    """Tests for AIDecision dataclass."""

    def test_basic_creation(self):
        d = AIDecision(
            role=AIRole.ARCHITECT,
            recommendation="Patch immediately",
            confidence=0.9,
            reasoning="Critical vulnerability",
            priority=1,
        )
        assert d.role == AIRole.ARCHITECT
        assert d.recommendation == "Patch immediately"
        assert d.confidence == 0.9
        assert d.priority == 1
        assert d.metadata == {}

    def test_with_metadata(self):
        d = AIDecision(
            role=AIRole.DEVELOPER,
            recommendation="Test",
            confidence=0.5,
            reasoning="Test",
            priority=5,
            metadata={"tools": ["burp"]},
        )
        assert d.metadata["tools"] == ["burp"]

    def test_dict_conversion(self):
        d = AIDecision(
            role=AIRole.LEAD,
            recommendation="Review",
            confidence=0.7,
            reasoning="Moderate risk",
            priority=3,
        )
        d_dict = d.__dict__
        assert "role" in d_dict
        assert d_dict["confidence"] == 0.7


# =========================================================================
# 4. ConsensusDecision dataclass tests
# =========================================================================

class TestConsensusDecision:
    """Tests for ConsensusDecision dataclass."""

    def test_basic_creation(self):
        cd = ConsensusDecision(
            action="execute_pentest",
            confidence=0.85,
            reasoning="High confidence consensus",
            contributing_decisions=[],
            execution_plan=[{"step": 1, "action": "Recon"}],
        )
        assert cd.action == "execute_pentest"
        assert cd.confidence == 0.85
        assert len(cd.execution_plan) == 1
        assert cd.metadata == {}

    def test_with_contributing_decisions(self):
        decisions = [
            AIDecision(AIRole.ARCHITECT, "a", 0.9, "r", 1),
            AIDecision(AIRole.DEVELOPER, "b", 0.8, "r", 2),
            AIDecision(AIRole.LEAD, "c", 0.7, "r", 3),
        ]
        cd = ConsensusDecision(
            action="test",
            confidence=0.8,
            reasoning="test",
            contributing_decisions=decisions,
            execution_plan=[],
        )
        assert len(cd.contributing_decisions) == 3


# =========================================================================
# 5. LLMCallError tests
# =========================================================================

class TestLLMCallError:
    """Tests for LLMCallError exception."""

    def test_is_exception(self):
        assert issubclass(LLMCallError, Exception)

    def test_message(self):
        err = LLMCallError("Provider failed")
        assert str(err) == "Provider failed"


# =========================================================================
# 6. MultiAIOrchestrator - helper methods (synchronous)
# =========================================================================

class TestOrchestratorHelpers:
    """Tests for MultiAIOrchestrator helper/private methods."""

    def setup_method(self):
        self.orch = _make_orchestrator()

    # _confidence_to_priority
    def test_confidence_to_priority_high(self):
        assert self.orch._confidence_to_priority(0.95) == 9

    def test_confidence_to_priority_mid(self):
        assert self.orch._confidence_to_priority(0.5) == 5

    def test_confidence_to_priority_low(self):
        assert self.orch._confidence_to_priority(0.1) == 1

    def test_confidence_to_priority_zero(self):
        # int(0 * 10) = 0, max(1, 0) = 1
        assert self.orch._confidence_to_priority(0.0) == 1

    def test_confidence_to_priority_one(self):
        assert self.orch._confidence_to_priority(1.0) == 10

    def test_confidence_to_priority_above_one(self):
        # min(10, int(1.5 * 10)) = min(10, 15) = 10
        assert self.orch._confidence_to_priority(1.5) == 10

    def test_confidence_to_priority_negative(self):
        # int(-0.5 * 10) = -5, max(1, -5) = 1
        assert self.orch._confidence_to_priority(-0.5) == 1

    # _suggest_tools
    def test_suggest_tools_injection(self):
        tools = self.orch._suggest_tools(["injection"])
        assert "sqlmap" in tools
        assert "burp" in tools

    def test_suggest_tools_sql_injection(self):
        tools = self.orch._suggest_tools(["sql_injection"])
        assert "sqlmap" in tools
        assert "sqlninja" in tools

    def test_suggest_tools_xss(self):
        tools = self.orch._suggest_tools(["xss"])
        assert "xsstrike" in tools
        assert "dalfox" in tools

    def test_suggest_tools_authentication_bypass(self):
        tools = self.orch._suggest_tools(["authentication_bypass"])
        assert "hydra" in tools

    def test_suggest_tools_rce(self):
        tools = self.orch._suggest_tools(["rce"])
        assert "metasploit" in tools
        assert "commix" in tools

    def test_suggest_tools_ssrf(self):
        tools = self.orch._suggest_tools(["ssrf"])
        assert "ssrfmap" in tools

    def test_suggest_tools_lfi(self):
        tools = self.orch._suggest_tools(["lfi"])
        assert "lfisuite" in tools

    def test_suggest_tools_xxe(self):
        tools = self.orch._suggest_tools(["xxe"])
        assert "xxeinjector" in tools

    def test_suggest_tools_unknown_vector(self):
        tools = self.orch._suggest_tools(["unknown_vector"])
        assert tools == ["burp", "manual"]

    def test_suggest_tools_empty(self):
        tools = self.orch._suggest_tools([])
        assert tools == ["burp", "manual"]

    def test_suggest_tools_multiple_vectors(self):
        tools = self.orch._suggest_tools(["injection", "xss", "rce"])
        assert "sqlmap" in tools
        assert "xsstrike" in tools
        assert "metasploit" in tools

    def test_suggest_tools_case_normalization(self):
        # "SQL Injection" -> "sql_injection" after lower+replace
        tools = self.orch._suggest_tools(["SQL Injection"])
        assert "sqlmap" in tools

    # _derive_strategy
    def test_derive_strategy_aggressive(self):
        r = _make_llm_response(confidence=0.85)
        assert self.orch._derive_strategy(r) == "Aggressive automated exploitation"

    def test_derive_strategy_multi_stage(self):
        r = _make_llm_response(confidence=0.7)
        assert self.orch._derive_strategy(r) == "Multi-stage exploitation with validation"

    def test_derive_strategy_conservative(self):
        r = _make_llm_response(confidence=0.5)
        assert self.orch._derive_strategy(r) == "Conservative testing with manual review"

    def test_derive_strategy_manual(self):
        r = _make_llm_response(confidence=0.3)
        assert self.orch._derive_strategy(r) == "Manual analysis recommended"

    def test_derive_strategy_boundary_08(self):
        r = _make_llm_response(confidence=0.8)
        # 0.8 is NOT > 0.8, so falls to next
        assert self.orch._derive_strategy(r) == "Multi-stage exploitation with validation"

    def test_derive_strategy_boundary_06(self):
        r = _make_llm_response(confidence=0.6)
        # 0.6 is NOT > 0.6, so falls to next
        assert self.orch._derive_strategy(r) == "Conservative testing with manual review"

    def test_derive_strategy_boundary_04(self):
        r = _make_llm_response(confidence=0.4)
        # 0.4 is NOT > 0.4, so falls to manual
        assert self.orch._derive_strategy(r) == "Manual analysis recommended"

    # _derive_success_criteria
    def test_derive_success_criteria_basic(self):
        r = _make_llm_response(compliance=[], mitre=[])
        criteria = self.orch._derive_success_criteria(r)
        assert "Vulnerability confirmed" in criteria
        assert "Evidence collected" in criteria
        assert len(criteria) == 2

    def test_derive_success_criteria_with_compliance(self):
        r = _make_llm_response(compliance=["PCI-DSS"])
        criteria = self.orch._derive_success_criteria(r)
        assert "Compliance impact documented" in criteria

    def test_derive_success_criteria_with_mitre(self):
        r = _make_llm_response(mitre=["T1190"])
        criteria = self.orch._derive_success_criteria(r)
        assert "MITRE ATT&CK mapping verified" in criteria

    def test_derive_success_criteria_full(self):
        r = _make_llm_response(compliance=["SOC2"], mitre=["T1059"])
        criteria = self.orch._derive_success_criteria(r)
        assert len(criteria) == 4

    # _assess_business_impact
    def test_business_impact_critical(self):
        r = _make_llm_response(confidence=0.9)
        assert "Critical" in self.orch._assess_business_impact(r)

    def test_business_impact_high(self):
        r = _make_llm_response(confidence=0.7)
        assert "High" in self.orch._assess_business_impact(r)

    def test_business_impact_medium(self):
        r = _make_llm_response(confidence=0.5)
        assert "Medium" in self.orch._assess_business_impact(r)

    def test_business_impact_low(self):
        r = _make_llm_response(confidence=0.3)
        assert "Low" in self.orch._assess_business_impact(r)

    def test_business_impact_boundary_08(self):
        r = _make_llm_response(confidence=0.8)
        assert "High" in self.orch._assess_business_impact(r)

    def test_business_impact_boundary_06(self):
        r = _make_llm_response(confidence=0.6)
        assert "Medium" in self.orch._assess_business_impact(r)

    def test_business_impact_boundary_04(self):
        r = _make_llm_response(confidence=0.4)
        assert "Low" in self.orch._assess_business_impact(r)

    # _fallback_decision
    def test_fallback_decision_architect(self):
        vuln = _make_vulnerability()
        d = self.orch._fallback_decision(AIRole.ARCHITECT, vuln)
        assert d.role == AIRole.ARCHITECT
        assert d.confidence == 0.5
        assert d.priority == 5
        assert d.metadata["fallback"] is True
        assert d.metadata["ai_generated"] is False
        assert d.metadata["vulnerability_id"] == "CVE-2024-1234"
        assert "DETERMINISTIC FALLBACK" in d.reasoning

    def test_fallback_decision_developer(self):
        d = self.orch._fallback_decision(AIRole.DEVELOPER, {"id": "X"})
        assert d.role == AIRole.DEVELOPER
        assert d.metadata["vulnerability_id"] == "X"

    def test_fallback_decision_lead(self):
        d = self.orch._fallback_decision(AIRole.LEAD, {})
        assert d.metadata["vulnerability_id"] == "unknown"

    def test_fallback_decision_has_audit_label(self):
        d = self.orch._fallback_decision(AIRole.ARCHITECT, {})
        assert d.metadata["audit_label"] == "FALLBACK_DETERMINISTIC_DECISION"

    def test_fallback_decision_recommendation(self):
        d = self.orch._fallback_decision(AIRole.DEVELOPER, {})
        assert d.recommendation == "Proceed with standard testing"

    # _fallback_consensus
    def test_fallback_consensus_basic(self):
        a = AIDecision(AIRole.ARCHITECT, "a", 0.9, "r", 1)
        b = AIDecision(AIRole.DEVELOPER, "b", 0.6, "r", 2)
        c = AIDecision(AIRole.LEAD, "c", 0.3, "r", 3)
        cs = self.orch._fallback_consensus(a, b, c)
        assert cs.action == "execute_pentest_with_caution"
        assert abs(cs.confidence - 0.6) < 0.01  # (0.9+0.6+0.3)/3
        assert len(cs.contributing_decisions) == 3
        assert len(cs.execution_plan) == 3
        assert cs.metadata["fallback"] is True
        assert cs.metadata["ai_generated"] is False

    def test_fallback_consensus_counts_contributing_fallbacks(self):
        a = AIDecision(AIRole.ARCHITECT, "a", 0.5, "r", 5, metadata={"fallback": True})
        b = AIDecision(AIRole.DEVELOPER, "b", 0.5, "r", 5, metadata={"fallback": True})
        c = AIDecision(AIRole.LEAD, "c", 0.5, "r", 5, metadata={})
        cs = self.orch._fallback_consensus(a, b, c)
        assert cs.metadata["contributing_fallback_count"] == 2
        assert "2/3" in cs.reasoning

    def test_fallback_consensus_zero_contributing_fallbacks(self):
        a = AIDecision(AIRole.ARCHITECT, "a", 0.8, "r", 2)
        b = AIDecision(AIRole.DEVELOPER, "b", 0.7, "r", 3)
        c = AIDecision(AIRole.LEAD, "c", 0.6, "r", 4)
        cs = self.orch._fallback_consensus(a, b, c)
        assert cs.metadata["contributing_fallback_count"] == 0

    def test_fallback_consensus_has_audit_label(self):
        a = AIDecision(AIRole.ARCHITECT, "a", 0.5, "r", 5)
        b = AIDecision(AIRole.DEVELOPER, "b", 0.5, "r", 5)
        c = AIDecision(AIRole.LEAD, "c", 0.5, "r", 5)
        cs = self.orch._fallback_consensus(a, b, c)
        assert cs.metadata["audit_label"] == "FALLBACK_DETERMINISTIC_CONSENSUS"

    def test_fallback_consensus_execution_plan_structure(self):
        a = AIDecision(AIRole.ARCHITECT, "a", 0.5, "r", 5)
        b = AIDecision(AIRole.DEVELOPER, "b", 0.5, "r", 5)
        c = AIDecision(AIRole.LEAD, "c", 0.5, "r", 5)
        cs = self.orch._fallback_consensus(a, b, c)
        steps = cs.execution_plan
        assert steps[0]["step"] == 1
        assert steps[0]["action"] == "Reconnaissance"
        assert steps[1]["step"] == 2
        assert steps[2]["step"] == 3

    # get_statistics
    def test_get_statistics_initial(self):
        stats = self.orch.get_statistics()
        assert stats["total_calls"] == 0
        assert stats["successful_calls"] == 0
        assert stats["fallback_calls"] == 0
        assert stats["success_rate"] == 0
        assert stats["fallback_rate"] == 0
        assert stats["decisions_made"] == 0
        assert stats["config"]["threshold"] == 0.6

    def test_get_statistics_after_calls(self):
        self.orch._call_count["total"] = 10
        self.orch._call_count["success"] = 7
        self.orch._call_count["fallback"] = 3
        self.orch.decision_history = [None, None]  # type: ignore
        stats = self.orch.get_statistics()
        assert stats["total_calls"] == 10
        assert stats["success_rate"] == 0.7
        assert stats["fallback_rate"] == 0.3
        assert stats["decisions_made"] == 2


# =========================================================================
# 7. MultiAIOrchestrator - async methods
# =========================================================================

class TestOrchestratorAsync:
    """Tests for async methods on MultiAIOrchestrator."""

    @pytest.mark.asyncio
    async def test_call_llm_success(self):
        resp = _make_llm_response(confidence=0.9)
        orch = _make_orchestrator(llm_response=resp)
        result_str = await orch._call_llm("openai", "test prompt")
        result = json.loads(result_str)
        assert result["confidence"] == 0.9
        assert result["recommendation"] == "execute_pentest"
        assert orch._call_count["success"] == 1

    @pytest.mark.asyncio
    async def test_call_llm_fallback_mode(self):
        resp = _make_llm_response(metadata={"mode": "deterministic", "reason": "no_key"})
        orch = _make_orchestrator(llm_response=resp)
        result_str = await orch._call_llm("openai", "test")
        result = json.loads(result_str)
        assert orch._call_count["fallback"] == 1

    @pytest.mark.asyncio
    async def test_call_llm_fallback_response_mode(self):
        resp = _make_llm_response(metadata={"mode": "fallback"})
        orch = _make_orchestrator(llm_response=resp)
        await orch._call_llm("gemini", "test")
        assert orch._call_count["fallback"] == 1

    @pytest.mark.asyncio
    async def test_call_llm_retry_then_succeed(self):
        resp = _make_llm_response()
        mgr = MagicMock()
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise ConnectionError("Temporary failure")
            return resp

        mgr.analyse.side_effect = side_effect
        config = _default_config()
        config.max_retries = 3
        config.timeout_seconds = 0.5
        orch = MultiAIOrchestrator(mgr, config)

        with patch("core.mpte_advanced.asyncio.sleep", new_callable=AsyncMock):
            result_str = await orch._call_llm("openai", "test")

        result = json.loads(result_str)
        assert result["confidence"] == 0.85
        assert orch._call_count["success"] == 1

    @pytest.mark.asyncio
    async def test_call_llm_all_retries_fail_with_fallback(self):
        mgr = MagicMock()
        mgr.analyse.side_effect = RuntimeError("Provider down")
        config = _default_config()
        config.max_retries = 2
        config.fallback_enabled = True
        config.timeout_seconds = 0.5
        orch = MultiAIOrchestrator(mgr, config)

        with patch("core.mpte_advanced.asyncio.sleep", new_callable=AsyncMock):
            result_str = await orch._call_llm("openai", "test")

        result = json.loads(result_str)
        assert result["recommendation"] == "Proceed with standard testing"
        assert result["confidence"] == 0.5
        assert result["metadata"]["fallback"] is True
        assert orch._call_count["fallback"] == 1

    @pytest.mark.asyncio
    async def test_call_llm_all_retries_fail_no_fallback(self):
        mgr = MagicMock()
        mgr.analyse.side_effect = RuntimeError("Provider down")
        config = _default_config()
        config.max_retries = 1
        config.fallback_enabled = False
        config.timeout_seconds = 0.5
        orch = MultiAIOrchestrator(mgr, config)

        with pytest.raises(LLMCallError, match="failed after 1 retries"):
            await orch._call_llm("openai", "test")

    @pytest.mark.asyncio
    async def test_call_llm_timeout(self):
        mgr = MagicMock()

        async def slow_analyse(*args, **kwargs):
            await asyncio.sleep(10)
            return _make_llm_response()

        # Make analyse block long enough to timeout
        mgr.analyse.side_effect = lambda *a, **kw: (_ for _ in ()).throw(
            TimeoutError("slow")
        )
        config = _default_config()
        config.max_retries = 1
        config.fallback_enabled = True
        config.timeout_seconds = 0.1
        orch = MultiAIOrchestrator(mgr, config)

        result_str = await orch._call_llm("openai", "test")
        result = json.loads(result_str)
        assert result["metadata"]["fallback"] is True

    @pytest.mark.asyncio
    async def test_call_llm_includes_tools_in_result(self):
        resp = _make_llm_response(attack_vectors=["injection", "xss"])
        orch = _make_orchestrator(llm_response=resp)
        result_str = await orch._call_llm("anthropic", "test")
        result = json.loads(result_str)
        assert "sqlmap" in result["tools"]
        assert "xsstrike" in result["tools"] or "dalfox" in result["tools"]

    @pytest.mark.asyncio
    async def test_call_llm_includes_strategy(self):
        resp = _make_llm_response(confidence=0.9)
        orch = _make_orchestrator(llm_response=resp)
        result_str = await orch._call_llm("openai", "test")
        result = json.loads(result_str)
        assert result["strategy"] == "Aggressive automated exploitation"

    @pytest.mark.asyncio
    async def test_call_llm_includes_business_impact(self):
        resp = _make_llm_response(confidence=0.3)
        orch = _make_orchestrator(llm_response=resp)
        result_str = await orch._call_llm("openai", "test")
        result = json.loads(result_str)
        assert "Low" in result["business_impact"]

    @pytest.mark.asyncio
    async def test_call_llm_includes_metadata_attempt(self):
        resp = _make_llm_response()
        orch = _make_orchestrator(llm_response=resp)
        result_str = await orch._call_llm("openai", "test")
        result = json.loads(result_str)
        assert result["metadata"]["attempt"] == 1
        assert result["metadata"]["provider"] == "openai"

    @pytest.mark.asyncio
    async def test_get_architect_decision_success(self):
        resp = _make_llm_response(
            action="patch", confidence=0.88, reasoning="Critical",
            attack_vectors=["injection"]
        )
        orch = _make_orchestrator(llm_response=resp)
        ctx = _make_context()
        vuln = _make_vulnerability()
        d = await orch.get_architect_decision(ctx, vuln)
        assert d.role == AIRole.ARCHITECT
        assert d.confidence == 0.88
        assert d.recommendation == "patch"

    @pytest.mark.asyncio
    async def test_get_architect_decision_fallback_on_error(self):
        orch = _make_orchestrator(llm_side_effect=RuntimeError("fail"))
        config = orch.config
        config.max_retries = 1
        config.fallback_enabled = False  # So _call_llm raises LLMCallError
        config.timeout_seconds = 0.5
        # get_architect_decision catches all exceptions -> fallback
        d = await orch.get_architect_decision({}, {"id": "V-1"})
        assert d.role == AIRole.ARCHITECT
        assert d.metadata["fallback"] is True

    @pytest.mark.asyncio
    async def test_get_developer_decision_success(self):
        resp = _make_llm_response(confidence=0.75)
        orch = _make_orchestrator(llm_response=resp)
        d = await orch.get_developer_decision({}, _make_vulnerability())
        assert d.role == AIRole.DEVELOPER

    @pytest.mark.asyncio
    async def test_get_developer_decision_fallback(self):
        orch = _make_orchestrator(llm_side_effect=RuntimeError("fail"))
        config = orch.config
        config.max_retries = 1
        config.fallback_enabled = False
        config.timeout_seconds = 0.5
        d = await orch.get_developer_decision({}, {"id": "V-2"})
        assert d.metadata["fallback"] is True

    @pytest.mark.asyncio
    async def test_get_lead_decision_success(self):
        resp = _make_llm_response(confidence=0.65)
        orch = _make_orchestrator(llm_response=resp)
        d = await orch.get_lead_decision({}, _make_vulnerability())
        assert d.role == AIRole.LEAD

    @pytest.mark.asyncio
    async def test_get_lead_decision_fallback(self):
        orch = _make_orchestrator(llm_side_effect=RuntimeError("fail"))
        config = orch.config
        config.max_retries = 1
        config.fallback_enabled = False
        config.timeout_seconds = 0.5
        d = await orch.get_lead_decision({}, {})
        assert d.metadata["fallback"] is True

    @pytest.mark.asyncio
    async def test_compose_consensus_success(self):
        resp = _make_llm_response(confidence=0.82)
        orch = _make_orchestrator(llm_response=resp)

        a = AIDecision(AIRole.ARCHITECT, "a", 0.9, "r", 1)
        b = AIDecision(AIRole.DEVELOPER, "b", 0.8, "r", 2)
        c = AIDecision(AIRole.LEAD, "c", 0.7, "r", 3)

        cs = await orch.compose_consensus(a, b, c, {})
        # Weighted: 0.9*0.35 + 0.8*0.40 + 0.7*0.25 = 0.315 + 0.32 + 0.175 = 0.81
        assert abs(cs.confidence - 0.81) < 0.01
        assert len(cs.contributing_decisions) == 3
        assert len(orch.decision_history) == 1

    @pytest.mark.asyncio
    async def test_compose_consensus_fallback_on_error(self):
        orch = _make_orchestrator(llm_side_effect=RuntimeError("fail"))
        config = orch.config
        config.max_retries = 1
        config.fallback_enabled = False
        config.timeout_seconds = 0.5

        a = AIDecision(AIRole.ARCHITECT, "a", 0.6, "r", 3)
        b = AIDecision(AIRole.DEVELOPER, "b", 0.6, "r", 3)
        c = AIDecision(AIRole.LEAD, "c", 0.6, "r", 3)

        cs = await orch.compose_consensus(a, b, c, {})
        # Falls to _fallback_consensus since compose_consensus catches exceptions
        assert cs.action == "execute_pentest_with_caution"
        assert cs.metadata["fallback"] is True

    @pytest.mark.asyncio
    async def test_compose_consensus_weighted_confidence(self):
        resp = _make_llm_response()
        orch = _make_orchestrator(llm_response=resp)

        a = AIDecision(AIRole.ARCHITECT, "a", 1.0, "r", 1)
        b = AIDecision(AIRole.DEVELOPER, "b", 1.0, "r", 1)
        c = AIDecision(AIRole.LEAD, "c", 1.0, "r", 1)

        cs = await orch.compose_consensus(a, b, c, {})
        # 1.0*0.35 + 1.0*0.40 + 1.0*0.25 = 1.0
        assert abs(cs.confidence - 1.0) < 0.01

    @pytest.mark.asyncio
    async def test_compose_consensus_stores_composer_confidence(self):
        resp = _make_llm_response(confidence=0.95)
        orch = _make_orchestrator(llm_response=resp)
        a = AIDecision(AIRole.ARCHITECT, "a", 0.8, "r", 2)
        b = AIDecision(AIRole.DEVELOPER, "b", 0.7, "r", 3)
        c = AIDecision(AIRole.LEAD, "c", 0.6, "r", 4)
        cs = await orch.compose_consensus(a, b, c, {})
        assert "composer_confidence" in cs.metadata
        assert "decision_timestamp" in cs.metadata

    @pytest.mark.asyncio
    async def test_orchestrator_init_with_default_config(self):
        """Test that orchestrator uses from_env when no config supplied."""
        mgr = _make_mock_llm_manager()
        orch = MultiAIOrchestrator(mgr)
        # Should use default env config
        assert orch.config.threshold == 0.6

    @pytest.mark.asyncio
    async def test_orchestrator_init_validates_config(self):
        """Config validation is called on init."""
        mgr = _make_mock_llm_manager()
        bad_config = ConsensusConfig(threshold=2.0)
        with pytest.raises(ValueError):
            MultiAIOrchestrator(mgr, bad_config)


# =========================================================================
# 8. ExploitValidationFramework tests
# =========================================================================

class TestExploitValidationFramework:
    """Tests for ExploitValidationFramework."""

    def _make_framework(self, execute_result=None):
        client = MagicMock()
        client.execute_pentest = AsyncMock(
            return_value=execute_result or {"exploit_successful": True, "confidence_score": 0.9}
        )
        return ExploitValidationFramework(client)

    @pytest.mark.asyncio
    async def test_validate_exploitability_confirmed(self):
        fw = self._make_framework({"exploit_successful": True, "confidence_score": 0.9})
        level, result = await fw.validate_exploitability(
            _make_vulnerability(), _make_context()
        )
        assert level == ExploitabilityLevel.CONFIRMED_EXPLOITABLE

    @pytest.mark.asyncio
    async def test_validate_exploitability_likely(self):
        fw = self._make_framework({"exploit_successful": True, "confidence_score": 0.6})
        level, _ = await fw.validate_exploitability(
            _make_vulnerability(), _make_context()
        )
        assert level == ExploitabilityLevel.LIKELY_EXPLOITABLE

    @pytest.mark.asyncio
    async def test_validate_exploitability_unexploitable(self):
        fw = self._make_framework({"exploit_successful": False, "confidence_score": 0.9})
        level, _ = await fw.validate_exploitability(
            _make_vulnerability(), _make_context()
        )
        assert level == ExploitabilityLevel.UNEXPLOITABLE

    @pytest.mark.asyncio
    async def test_validate_exploitability_blocked(self):
        fw = self._make_framework(
            {"exploit_successful": False, "confidence_score": 0.3, "blocked": True}
        )
        level, _ = await fw.validate_exploitability(
            _make_vulnerability(), _make_context()
        )
        assert level == ExploitabilityLevel.BLOCKED

    @pytest.mark.asyncio
    async def test_validate_exploitability_inconclusive(self):
        fw = self._make_framework(
            {"exploit_successful": False, "confidence_score": 0.3}
        )
        level, _ = await fw.validate_exploitability(
            _make_vulnerability(), _make_context()
        )
        assert level == ExploitabilityLevel.INCONCLUSIVE

    @pytest.mark.asyncio
    async def test_validate_exploitability_cache_hit(self):
        fw = self._make_framework()
        vuln = _make_vulnerability(vuln_id="CACHED-1")
        fw.validation_cache["CACHED-1"] = ExploitabilityLevel.BLOCKED
        level, result = await fw.validate_exploitability(vuln, {})
        assert level == ExploitabilityLevel.BLOCKED
        assert result == {"cached": True}
        # execute_pentest should NOT be called
        fw.mpte_client.execute_pentest.assert_not_called()

    @pytest.mark.asyncio
    async def test_validate_exploitability_error_returns_inconclusive(self):
        client = MagicMock()
        client.execute_pentest = AsyncMock(side_effect=RuntimeError("API down"))
        fw = ExploitValidationFramework(client)
        level, result = await fw.validate_exploitability(
            _make_vulnerability(), _make_context()
        )
        assert level == ExploitabilityLevel.INCONCLUSIVE
        assert "error" in result

    @pytest.mark.asyncio
    async def test_validate_exploitability_caches_result(self):
        fw = self._make_framework({"exploit_successful": True, "confidence_score": 0.9})
        vuln = _make_vulnerability(vuln_id="CACHE-ME")
        await fw.validate_exploitability(vuln, _make_context())
        assert "CACHE-ME" in fw.validation_cache
        assert fw.validation_cache["CACHE-ME"] == ExploitabilityLevel.CONFIRMED_EXPLOITABLE

    @pytest.mark.asyncio
    async def test_validate_unknown_vuln_id(self):
        fw = self._make_framework()
        level, _ = await fw.validate_exploitability({}, {})
        # vuln_id defaults to "unknown"
        assert "unknown" in fw.validation_cache

    # _create_test_request
    def test_create_test_request_basic(self):
        fw = self._make_framework()
        vuln = _make_vulnerability()
        ctx = _make_context()
        req = fw._create_test_request(vuln, ctx)
        assert isinstance(req, PenTestRequest)
        assert req.finding_id == "CVE-2024-1234"
        assert req.target_url == "https://target.example.com"
        assert req.vulnerability_type == "SQL Injection"
        assert req.priority == PenTestPriority.HIGH
        assert req.metadata["validation_mode"] is True

    def test_create_test_request_defaults(self):
        fw = self._make_framework()
        req = fw._create_test_request({}, {})
        assert req.finding_id == "unknown"
        assert req.target_url == "http://localhost"
        assert req.vulnerability_type == "Unknown"
        assert req.priority == PenTestPriority.MEDIUM

    # _generate_test_case
    def test_generate_test_case(self):
        fw = self._make_framework()
        vuln = _make_vulnerability()
        tc = fw._generate_test_case(vuln)
        assert "SQL Injection Validation" in tc
        assert "SQL injection in login form" in tc
        assert "Verify the vulnerability exists" in tc

    def test_generate_test_case_empty_vuln(self):
        fw = self._make_framework()
        tc = fw._generate_test_case({})
        assert "Unknown Validation" in tc

    # _map_priority
    def test_map_priority_critical(self):
        fw = self._make_framework()
        assert fw._map_priority("critical") == PenTestPriority.CRITICAL

    def test_map_priority_high(self):
        fw = self._make_framework()
        assert fw._map_priority("high") == PenTestPriority.HIGH

    def test_map_priority_medium(self):
        fw = self._make_framework()
        assert fw._map_priority("medium") == PenTestPriority.MEDIUM

    def test_map_priority_low(self):
        fw = self._make_framework()
        assert fw._map_priority("low") == PenTestPriority.LOW

    def test_map_priority_case_insensitive(self):
        fw = self._make_framework()
        assert fw._map_priority("HIGH") == PenTestPriority.HIGH
        assert fw._map_priority("Critical") == PenTestPriority.CRITICAL

    def test_map_priority_unknown_defaults_medium(self):
        fw = self._make_framework()
        assert fw._map_priority("urgent") == PenTestPriority.MEDIUM
        assert fw._map_priority("informational") == PenTestPriority.MEDIUM

    # _analyze_test_results
    def test_analyze_empty_result(self):
        fw = self._make_framework()
        assert fw._analyze_test_results({}) == ExploitabilityLevel.INCONCLUSIVE

    def test_analyze_none_result(self):
        fw = self._make_framework()
        assert fw._analyze_test_results(None) == ExploitabilityLevel.INCONCLUSIVE

    def test_analyze_confirmed_exploitable(self):
        fw = self._make_framework()
        result = {"exploit_successful": True, "confidence_score": 0.9}
        assert fw._analyze_test_results(result) == ExploitabilityLevel.CONFIRMED_EXPLOITABLE

    def test_analyze_likely_exploitable(self):
        fw = self._make_framework()
        result = {"exploit_successful": True, "confidence_score": 0.6}
        assert fw._analyze_test_results(result) == ExploitabilityLevel.LIKELY_EXPLOITABLE

    def test_analyze_boundary_exploit_confidence_08(self):
        fw = self._make_framework()
        # exploit_successful=True, confidence=0.8, NOT > 0.8 -> LIKELY
        result = {"exploit_successful": True, "confidence_score": 0.8}
        assert fw._analyze_test_results(result) == ExploitabilityLevel.LIKELY_EXPLOITABLE

    def test_analyze_boundary_exploit_confidence_05(self):
        fw = self._make_framework()
        # exploit_successful=True, confidence=0.5, NOT > 0.5 -> falls through
        # Not CONFIRMED, not LIKELY... not unexploitable... not blocked -> INCONCLUSIVE
        result = {"exploit_successful": True, "confidence_score": 0.5}
        assert fw._analyze_test_results(result) == ExploitabilityLevel.INCONCLUSIVE

    def test_analyze_unexploitable(self):
        fw = self._make_framework()
        result = {"exploit_successful": False, "confidence_score": 0.9}
        assert fw._analyze_test_results(result) == ExploitabilityLevel.UNEXPLOITABLE

    def test_analyze_blocked(self):
        fw = self._make_framework()
        result = {"exploit_successful": False, "confidence_score": 0.3, "blocked": True}
        assert fw._analyze_test_results(result) == ExploitabilityLevel.BLOCKED

    def test_analyze_blocked_high_confidence(self):
        fw = self._make_framework()
        # exploit_successful=False, confidence=0.9 -> UNEXPLOITABLE (checked before blocked)
        result = {"exploit_successful": False, "confidence_score": 0.9, "blocked": True}
        assert fw._analyze_test_results(result) == ExploitabilityLevel.UNEXPLOITABLE

    def test_analyze_inconclusive_low_confidence(self):
        fw = self._make_framework()
        result = {"exploit_successful": False, "confidence_score": 0.3}
        assert fw._analyze_test_results(result) == ExploitabilityLevel.INCONCLUSIVE


# =========================================================================
# 9. AdvancedMPTEClient tests
# =========================================================================

class TestAdvancedMPTEClient:
    """Tests for AdvancedMPTEClient."""

    def _make_client(self, db=None, llm_response=None):
        cfg = _make_pentest_config()
        mgr = _make_mock_llm_manager(llm_response or _make_llm_response())
        mock_db = db or _make_mock_db()
        client = AdvancedMPTEClient(cfg, mgr, mock_db)
        return client

    @pytest.mark.asyncio
    async def test_context_manager_enter_exit(self):
        client = self._make_client()
        async with client as c:
            assert c.session is not None
        # session.close should have been called
        # (aiohttp.ClientSession is created in __aenter__)

    @pytest.mark.asyncio
    async def test_context_manager_closes_session(self):
        client = self._make_client()
        mock_session = AsyncMock()
        client.session = mock_session
        await client.__aexit__(None, None, None)
        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager_no_session(self):
        client = self._make_client()
        client.session = None
        await client.__aexit__(None, None, None)
        # Should not raise

    def test_client_has_orchestrator(self):
        client = self._make_client()
        assert isinstance(client.orchestrator, MultiAIOrchestrator)

    def test_client_has_validator(self):
        client = self._make_client()
        assert isinstance(client.validator, ExploitValidationFramework)
        assert client.validator.mpte_client is client

    # execute_pentest
    @pytest.mark.asyncio
    async def test_execute_pentest_success(self):
        db = _make_mock_db()
        client = self._make_client(db=db)

        mock_result = {
            "job_id": "job-1",
            "exploit_successful": True,
            "exploitability": "confirmed_exploitable",
            "confidence_score": 0.9,
            "evidence": "Shell access obtained",
            "steps_taken": ["recon", "exploit"],
            "artifacts": ["screenshot.png"],
            "execution_time_seconds": 15.0,
        }

        with patch.object(client, "_call_mpte_api", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_result
            req = PenTestRequest(
                id="",
                finding_id="CVE-2024-5678",
                target_url="https://target.test",
                vulnerability_type="RCE",
                test_case="Test RCE",
                priority=PenTestPriority.CRITICAL,
            )
            result = await client.execute_pentest(req)

        assert result["job_id"] == "job-1"
        db.create_request.assert_called_once()
        assert db.update_request.call_count == 2  # RUNNING, then COMPLETED
        db.create_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_pentest_failure_updates_status(self):
        db = _make_mock_db()
        client = self._make_client(db=db)

        with patch.object(client, "_call_mpte_api", new_callable=AsyncMock) as mock_api:
            mock_api.side_effect = RuntimeError("API down")
            req = PenTestRequest(
                id="",
                finding_id="CVE-2024-9999",
                target_url="https://target.test",
                vulnerability_type="XSS",
                test_case="Test XSS",
                priority=PenTestPriority.HIGH,
            )
            with pytest.raises(RuntimeError, match="API down"):
                await client.execute_pentest(req)

        # Should have updated to RUNNING, then FAILED
        assert db.update_request.call_count == 2
        last_update_arg = db.update_request.call_args_list[1][0][0]
        assert last_update_arg.status == PenTestStatus.FAILED

    # _create_inconclusive_response
    def test_create_inconclusive_response(self):
        client = self._make_client()
        req = PenTestRequest(
            id="req-42",
            finding_id="CVE-2024-0001",
            target_url="https://target.test",
            vulnerability_type="SSRF",
            test_case="Test SSRF",
            priority=PenTestPriority.MEDIUM,
        )
        resp = client._create_inconclusive_response(req, "Connection refused")
        assert resp["job_id"] == "inconclusive-req-42"
        assert resp["status"] == "failed"
        assert resp["exploit_successful"] is False
        assert resp["exploitability"] == "inconclusive"
        assert resp["confidence_score"] == 0.0
        assert "Connection refused" in resp["evidence"]
        assert resp["error"] == "Connection refused"

    # _create_result_from_response
    def test_create_result_from_response_confirmed(self):
        client = self._make_client()
        req = PenTestRequest(
            id="req-1",
            finding_id="F-1",
            target_url="https://t.test",
            vulnerability_type="SQLi",
            test_case="tc",
            priority=PenTestPriority.HIGH,
        )
        response = {
            "exploitability": "confirmed_exploitable",
            "exploit_successful": True,
            "evidence": "DB dump obtained",
            "steps_taken": ["s1", "s2"],
            "artifacts": ["dump.sql"],
            "confidence_score": 0.95,
            "execution_time_seconds": 12.5,
        }
        result = client._create_result_from_response(req, response)
        assert isinstance(result, PenTestResult)
        assert result.request_id == "req-1"
        assert result.finding_id == "F-1"
        assert result.exploitability == ExploitabilityLevel.CONFIRMED_EXPLOITABLE
        assert result.exploit_successful is True
        assert result.confidence_score == 0.95

    def test_create_result_from_response_defaults(self):
        client = self._make_client()
        req = PenTestRequest(
            id="req-2", finding_id="F-2", target_url="t", vulnerability_type="x",
            test_case="tc", priority=PenTestPriority.LOW,
        )
        result = client._create_result_from_response(req, {})
        assert result.exploitability == ExploitabilityLevel.INCONCLUSIVE
        assert result.exploit_successful is False
        assert result.evidence == "No evidence collected"
        assert result.confidence_score == 0.0

    def test_create_result_from_response_all_exploitability_levels(self):
        client = self._make_client()
        req = PenTestRequest(
            id="r", finding_id="f", target_url="t", vulnerability_type="x",
            test_case="tc", priority=PenTestPriority.MEDIUM,
        )
        mapping = {
            "confirmed_exploitable": ExploitabilityLevel.CONFIRMED_EXPLOITABLE,
            "likely_exploitable": ExploitabilityLevel.LIKELY_EXPLOITABLE,
            "unexploitable": ExploitabilityLevel.UNEXPLOITABLE,
            "blocked": ExploitabilityLevel.BLOCKED,
            "inconclusive": ExploitabilityLevel.INCONCLUSIVE,
        }
        for key, expected in mapping.items():
            result = client._create_result_from_response(req, {"exploitability": key})
            assert result.exploitability == expected, f"Failed for {key}"

    def test_create_result_from_response_unknown_exploitability(self):
        client = self._make_client()
        req = PenTestRequest(
            id="r", finding_id="f", target_url="t", vulnerability_type="x",
            test_case="tc", priority=PenTestPriority.MEDIUM,
        )
        result = client._create_result_from_response(req, {"exploitability": "not_a_real_level"})
        assert result.exploitability == ExploitabilityLevel.INCONCLUSIVE

    # validate_remediation
    @pytest.mark.asyncio
    async def test_validate_remediation_no_original(self):
        db = _make_mock_db()
        db.list_requests.return_value = []
        client = self._make_client(db=db)
        success, msg = await client.validate_remediation("F-1", {})
        assert success is False
        assert "No original test found" in msg

    @pytest.mark.asyncio
    async def test_validate_remediation_still_exploitable(self):
        db = _make_mock_db()
        original_req = PenTestRequest(
            id="orig-1",
            finding_id="F-1",
            target_url="https://t.test",
            vulnerability_type="XSS",
            test_case="original test",
            priority=PenTestPriority.HIGH,
        )
        db.list_requests.return_value = [original_req]

        client = self._make_client(db=db)
        with patch.object(client, "execute_pentest", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {"exploit_successful": True}
            success, msg = await client.validate_remediation("F-1", {})
        assert success is False
        assert "still exploitable" in msg

    @pytest.mark.asyncio
    async def test_validate_remediation_fixed(self):
        db = _make_mock_db()
        original_req = PenTestRequest(
            id="orig-2",
            finding_id="F-2",
            target_url="https://t.test",
            vulnerability_type="SQLi",
            test_case="original test",
            priority=PenTestPriority.MEDIUM,
        )
        db.list_requests.return_value = [original_req]

        client = self._make_client(db=db)
        with patch.object(client, "execute_pentest", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {"exploit_successful": False}
            success, msg = await client.validate_remediation("F-2", {})
        assert success is True
        assert "successfully remediated" in msg

    @pytest.mark.asyncio
    async def test_validate_remediation_error(self):
        db = _make_mock_db()
        original_req = PenTestRequest(
            id="orig-3",
            finding_id="F-3",
            target_url="https://t.test",
            vulnerability_type="RCE",
            test_case="original",
            priority=PenTestPriority.CRITICAL,
        )
        db.list_requests.return_value = [original_req]

        client = self._make_client(db=db)
        with patch.object(client, "execute_pentest", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = RuntimeError("Connection lost")
            success, msg = await client.validate_remediation("F-3", {})
        assert success is False
        assert "Validation error" in msg

    @pytest.mark.asyncio
    async def test_validate_remediation_appends_retest_marker(self):
        db = _make_mock_db()
        original_req = PenTestRequest(
            id="orig-4",
            finding_id="F-4",
            target_url="https://t.test",
            vulnerability_type="SSRF",
            test_case="original test case",
            priority=PenTestPriority.HIGH,
        )
        db.list_requests.return_value = [original_req]

        captured_req = []
        client = self._make_client(db=db)

        async def capture_exec(req):
            captured_req.append(req)
            return {"exploit_successful": False}

        with patch.object(client, "execute_pentest", side_effect=capture_exec):
            await client.validate_remediation("F-4", {})

        assert len(captured_req) == 1
        assert "REMEDIATION VALIDATION TEST" in captured_req[0].test_case
        assert captured_req[0].metadata["retest"] is True
        assert captured_req[0].metadata["original_request_id"] == "orig-4"

    # get_statistics
    def test_get_statistics_empty(self):
        db = _make_mock_db()
        db.list_requests.return_value = []
        db.list_results.return_value = []
        client = self._make_client(db=db)
        stats = client.get_statistics()
        assert stats["total_tests"] == 0
        assert stats["completed_tests"] == 0
        assert stats["failed_tests"] == 0
        assert stats["success_rate"] == 0
        assert stats["confirmed_exploitable"] == 0
        assert stats["false_positives"] == 0
        assert stats["false_positive_rate"] == 0
        assert stats["average_execution_time_seconds"] == 0

    def test_get_statistics_with_data(self):
        db = _make_mock_db()

        req_completed = MagicMock()
        req_completed.status = PenTestStatus.COMPLETED
        req_failed = MagicMock()
        req_failed.status = PenTestStatus.FAILED
        req_pending = MagicMock()
        req_pending.status = PenTestStatus.PENDING

        db.list_requests.return_value = [req_completed, req_failed, req_pending]

        res_confirmed = MagicMock()
        res_confirmed.exploitability = ExploitabilityLevel.CONFIRMED_EXPLOITABLE
        res_confirmed.execution_time_seconds = 10.0

        res_unexploitable = MagicMock()
        res_unexploitable.exploitability = ExploitabilityLevel.UNEXPLOITABLE
        res_unexploitable.execution_time_seconds = 5.0

        db.list_results.return_value = [res_confirmed, res_unexploitable]

        client = self._make_client(db=db)
        stats = client.get_statistics()
        assert stats["total_tests"] == 3
        assert stats["completed_tests"] == 1
        assert stats["failed_tests"] == 1
        assert abs(stats["success_rate"] - 1 / 3) < 0.01
        assert stats["confirmed_exploitable"] == 1
        assert stats["false_positives"] == 1
        assert stats["false_positive_rate"] == 0.5
        assert stats["average_execution_time_seconds"] == 7.5

    # _call_mpte_api
    @pytest.mark.asyncio
    async def test_call_mpte_api_success(self):
        client = self._make_client()
        req = PenTestRequest(
            id="req-api-1",
            finding_id="CVE-2024-1111",
            target_url="https://target.test",
            vulnerability_type="SQLi",
            test_case="Test SQLi",
            priority=PenTestPriority.HIGH,
        )

        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={"job_id": "j-1", "exploit_successful": True})

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=False),
        ))

        client.session = mock_session
        result = await client._call_mpte_api(req)
        assert result["job_id"] == "j-1"

    @pytest.mark.asyncio
    async def test_call_mpte_api_error_returns_inconclusive(self):
        client = self._make_client()
        req = PenTestRequest(
            id="req-api-2",
            finding_id="CVE-2024-2222",
            target_url="https://target.test",
            vulnerability_type="XSS",
            test_case="Test XSS",
            priority=PenTestPriority.MEDIUM,
        )

        mock_session = MagicMock()
        mock_session.post = MagicMock(side_effect=Exception("Connection refused"))
        client.session = mock_session

        result = await client._call_mpte_api(req)
        assert result["status"] == "failed"
        assert result["exploitability"] == "inconclusive"
        assert "Connection refused" in result["error"]

    @pytest.mark.asyncio
    async def test_call_mpte_api_creates_session_if_none(self):
        client = self._make_client()
        client.session = None
        req = PenTestRequest(
            id="req-api-3",
            finding_id="F-3",
            target_url="t",
            vulnerability_type="x",
            test_case="tc",
            priority=PenTestPriority.LOW,
        )

        with patch("core.mpte_advanced.aiohttp.ClientSession") as mock_cls:
            mock_session = MagicMock()
            mock_session.post = MagicMock(side_effect=Exception("fail"))
            mock_cls.return_value = mock_session
            result = await client._call_mpte_api(req)

        assert result["status"] == "failed"
        mock_cls.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_mpte_api_sends_correct_payload(self):
        client = self._make_client()
        req = PenTestRequest(
            id="req-pay",
            finding_id="CVE-PAY",
            target_url="https://pay.test",
            vulnerability_type="RCE",
            test_case="Payload test case",
            priority=PenTestPriority.CRITICAL,
        )

        captured_kwargs = {}
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={"job_id": "j-pay"})

        class FakeContextManager:
            async def __aenter__(self):
                return mock_response
            async def __aexit__(self, *args):
                pass

        mock_session = MagicMock()
        def capture_post(url, **kwargs):
            captured_kwargs.update(kwargs)
            captured_kwargs["url"] = url
            return FakeContextManager()

        mock_session.post = capture_post
        client.session = mock_session

        await client._call_mpte_api(req)

        assert captured_kwargs["url"] == "https://mpte.example.com/api/v1/flows"
        payload = captured_kwargs["json"]
        assert payload["name"] == "FixOps Validation - CVE-PAY"
        assert payload["target"] == "https://pay.test"
        assert payload["vulnerability_type"] == "RCE"
        assert payload["priority"] == "critical"
        assert "Authorization" in captured_kwargs["headers"]
        assert captured_kwargs["headers"]["Authorization"] == "Bearer test-key"

    @pytest.mark.asyncio
    async def test_call_mpte_api_no_api_key(self):
        cfg = PenTestConfig(
            id="cfg-nokey",
            name="nokey",
            mpte_url="https://mpte.example.com",
            api_key=None,
        )
        mgr = _make_mock_llm_manager()
        client = AdvancedMPTEClient(cfg, mgr, _make_mock_db())

        captured_headers = {}
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={"job_id": "j"})

        class FakeCtx:
            async def __aenter__(self):
                return mock_response
            async def __aexit__(self, *args):
                pass

        mock_session = MagicMock()
        def cap(url, **kw):
            captured_headers.update(kw.get("headers", {}))
            return FakeCtx()

        mock_session.post = cap
        client.session = mock_session
        await client._call_mpte_api(PenTestRequest(
            id="r", finding_id="f", target_url="t", vulnerability_type="x",
            test_case="tc", priority=PenTestPriority.LOW,
        ))
        assert "Authorization" not in captured_headers

    # execute_pentest_with_consensus
    @pytest.mark.asyncio
    async def test_execute_pentest_with_consensus_high_confidence(self):
        resp = _make_llm_response(confidence=0.85)
        db = _make_mock_db()
        cfg = _make_pentest_config()
        mgr = _make_mock_llm_manager(resp)
        client = AdvancedMPTEClient(cfg, mgr, db)

        with patch.object(
            client, "_execute_consensus_plan", new_callable=AsyncMock
        ) as mock_plan:
            mock_plan.return_value = {"overall_success": True, "steps_executed": 3}
            result = await client.execute_pentest_with_consensus(
                _make_vulnerability(), _make_context()
            )
        assert result["status"] == "completed"
        assert "consensus" in result

    @pytest.mark.asyncio
    async def test_execute_pentest_with_consensus_low_confidence(self):
        resp = _make_llm_response(confidence=0.3)
        db = _make_mock_db()
        cfg = _make_pentest_config()
        mgr = _make_mock_llm_manager(resp)
        client = AdvancedMPTEClient(cfg, mgr, db)

        result = await client.execute_pentest_with_consensus(
            _make_vulnerability(), _make_context()
        )
        assert result["status"] == "manual_review_required"

    # _execute_consensus_plan
    @pytest.mark.asyncio
    async def test_execute_consensus_plan_all_steps(self):
        client = self._make_client()
        consensus = ConsensusDecision(
            action="test",
            confidence=0.8,
            reasoning="r",
            contributing_decisions=[],
            execution_plan=[
                {"step": 1, "action": "Recon", "tool": "nmap"},
                {"step": 2, "action": "Exploit", "tool": "metasploit"},
            ],
        )
        with patch.object(client, "_execute_step", new_callable=AsyncMock) as mock_step:
            mock_step.return_value = {"success": True}
            result = await client._execute_consensus_plan(
                consensus, _make_vulnerability(), _make_context()
            )
        assert result["steps_executed"] == 2
        assert result["overall_success"] is True

    @pytest.mark.asyncio
    async def test_execute_consensus_plan_stops_on_critical_failure(self):
        client = self._make_client()
        consensus = ConsensusDecision(
            action="test",
            confidence=0.8,
            reasoning="r",
            contributing_decisions=[],
            execution_plan=[
                {"step": 1, "action": "Recon"},
                {"step": 2, "action": "Exploit"},
                {"step": 3, "action": "Report"},
            ],
        )

        call_count = [0]

        async def mock_step(step, vuln, ctx):
            call_count[0] += 1
            if call_count[0] == 2:
                return {"success": False, "critical_failure": True}
            return {"success": True}

        with patch.object(client, "_execute_step", side_effect=mock_step):
            result = await client._execute_consensus_plan(
                consensus, _make_vulnerability(), _make_context()
            )
        assert result["steps_executed"] == 2
        assert result["overall_success"] is False

    @pytest.mark.asyncio
    async def test_execute_consensus_plan_empty_plan(self):
        client = self._make_client()
        consensus = ConsensusDecision(
            action="test", confidence=0.8, reasoning="r",
            contributing_decisions=[], execution_plan=[],
        )
        result = await client._execute_consensus_plan(
            consensus, _make_vulnerability(), _make_context()
        )
        assert result["steps_executed"] == 0
        assert result["overall_success"] is True

    # _execute_step
    @pytest.mark.asyncio
    async def test_execute_step(self):
        client = self._make_client()
        step = {"action": "Recon", "tool": "nmap"}
        with patch("core.mpte_advanced.asyncio.sleep", new_callable=AsyncMock):
            result = await client._execute_step(step, {}, {})
        assert result["success"] is True
        assert "Recon" in result["output"]
        assert "nmap" in result["output"]

    @pytest.mark.asyncio
    async def test_execute_step_default_tool(self):
        client = self._make_client()
        step = {"action": "Custom scan"}
        with patch("core.mpte_advanced.asyncio.sleep", new_callable=AsyncMock):
            result = await client._execute_step(step, {}, {})
        assert "automated" in result["output"]

    @pytest.mark.asyncio
    async def test_execute_step_unknown_action(self):
        client = self._make_client()
        step = {}
        with patch("core.mpte_advanced.asyncio.sleep", new_callable=AsyncMock):
            result = await client._execute_step(step, {}, {})
        assert "unknown" in result["output"]
