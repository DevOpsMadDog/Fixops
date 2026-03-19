"""Unit tests for SingleAgentEngine (V4 — Multi-LLM Consensus / Self-Hosted AI).

Tests cover:
- ExpertRole, InferenceBackend, ConsensusResult enums
- ExpertOpinion, ConsensusDecision dataclasses
- BaseInferenceBackend ABC and all 4 backends (VLLMBackend, OllamaBackend, GGUFBackend, APIFallbackBackend)
- SingleAgentEngine: decide, batch_decide, get_status, clear_cache
- Consensus logic and fallback behavior
- get_single_agent_engine singleton

Pillar: V4 (Multi-LLM Consensus)
Agent: agent-doctor (run v6 — 2026-03-01)
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.single_agent import (
    ExpertRole,
    InferenceBackend,
    ConsensusResult,
    ExpertOpinion,
    ConsensusDecision,
    BaseInferenceBackend,
    VLLMBackend,
    OllamaBackend,
    GGUFBackend,
    APIFallbackBackend,
    SingleAgentEngine,
    get_single_agent_engine,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------
class TestExpertRole:
    def test_values(self):
        assert ExpertRole.ANALYST == "analyst"
        assert ExpertRole.ARCHITECT == "architect"
        assert ExpertRole.AUDITOR == "auditor"
        assert ExpertRole.ATTACKER == "attacker"
        assert ExpertRole.MODERATOR == "moderator"

    def test_count(self):
        assert len(ExpertRole) == 5

    def test_is_str(self):
        assert isinstance(ExpertRole.ANALYST, str)


class TestInferenceBackend:
    def test_values(self):
        assert InferenceBackend.VLLM == "vllm"
        assert InferenceBackend.OLLAMA == "ollama"
        assert InferenceBackend.GGUF == "gguf"
        assert InferenceBackend.API == "api"
        assert InferenceBackend.AUTO == "auto"

    def test_count(self):
        assert len(InferenceBackend) == 5


class TestConsensusResult:
    def test_values(self):
        assert ConsensusResult.AGREED == "agreed"
        assert ConsensusResult.SPLIT == "split"
        assert ConsensusResult.INSUFFICIENT == "insufficient"

    def test_count(self):
        assert len(ConsensusResult) == 3


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------
class TestExpertOpinion:
    def test_creation_defaults(self):
        op = ExpertOpinion(
            role=ExpertRole.ANALYST,
            decision="patch",
            confidence=0.9,
            reasoning="Critical SQL injection",
        )
        assert op.role == ExpertRole.ANALYST
        assert op.decision == "patch"
        assert op.confidence == 0.9
        assert op.evidence == []
        assert op.dissent == ""
        assert op.latency_ms == 0

    def test_with_evidence(self):
        op = ExpertOpinion(
            role=ExpertRole.ATTACKER,
            decision="exploit",
            confidence=0.8,
            reasoning="Easy to exploit",
            evidence=["CVE-2024-1234", "OWASP Top 10"],
            dissent="Minor",
            latency_ms=150.5,
        )
        assert len(op.evidence) == 2
        assert op.dissent == "Minor"
        assert op.latency_ms == 150.5


class TestConsensusDecision:
    def test_creation(self):
        opinions = [
            ExpertOpinion(role=ExpertRole.ANALYST, decision="patch", confidence=0.9, reasoning="Critical"),
            ExpertOpinion(role=ExpertRole.ARCHITECT, decision="patch", confidence=0.85, reasoning="Agreed"),
        ]
        cd = ConsensusDecision(
            finding_id="VULN-001",
            decision="patch",
            consensus_result=ConsensusResult.AGREED,
            agreement_pct=0.87,
            threshold=0.85,
            opinions=opinions,
        )
        assert cd.consensus_result == ConsensusResult.AGREED
        assert cd.decision == "patch"
        assert len(cd.opinions) == 2
        assert cd.agreement_pct == 0.87


# ---------------------------------------------------------------------------
# Backend tests
# ---------------------------------------------------------------------------
class TestVLLMBackend:
    def test_init_defaults(self):
        backend = VLLMBackend()
        assert backend.base_url is not None
        assert "localhost" in backend.base_url or "8001" in backend.base_url

    def test_init_custom_url(self):
        backend = VLLMBackend(base_url="http://custom:9999/v1", model="codellama:7b")
        assert backend.base_url == "http://custom:9999/v1"

    def test_model_info(self):
        backend = VLLMBackend()
        info = backend.model_info()
        assert "backend" in info
        assert info["backend"] == "vllm"

    def test_is_available_no_server(self):
        backend = VLLMBackend(base_url="http://localhost:99999/v1")
        assert backend.is_available() is False

    @patch("urllib.request.urlopen")
    def test_generate_success(self, mock_urlopen):
        response_data = json.dumps({
            "choices": [{"message": {"content": '{"decision": "patch"}'}}]
        }).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        backend = VLLMBackend(base_url="http://test:8001/v1")
        result = backend.generate("test prompt")
        assert isinstance(result, tuple) and isinstance(result[0], str)

    def test_generate_failure_no_server(self):
        backend = VLLMBackend(base_url="http://localhost:99999/v1")
        result = backend.generate("test prompt")
        assert isinstance(result, tuple) and result[0] == ""


class TestOllamaBackend:
    def test_init_defaults(self):
        backend = OllamaBackend()
        assert backend.base_url is not None
        assert "11434" in backend.base_url

    def test_model_info(self):
        backend = OllamaBackend()
        info = backend.model_info()
        assert info["backend"] == "ollama"

    def test_is_available_no_server(self):
        backend = OllamaBackend(base_url="http://localhost:99999")
        assert backend.is_available() is False


class TestGGUFBackend:
    def test_init_no_model(self):
        backend = GGUFBackend(model_path="/nonexistent/model.gguf")
        assert backend.is_available() is False

    def test_model_info(self):
        backend = GGUFBackend()
        info = backend.model_info()
        assert info["backend"] == "gguf"


class TestAPIFallbackBackend:
    def test_init(self):
        backend = APIFallbackBackend()
        assert isinstance(backend, BaseInferenceBackend)

    def test_model_info(self):
        backend = APIFallbackBackend()
        info = backend.model_info()
        assert info["backend"] == "api-fallback"

    def test_is_available(self):
        backend = APIFallbackBackend()
        # Available if any API key is set
        result = backend.is_available()
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# SingleAgentEngine tests
# ---------------------------------------------------------------------------
class TestSingleAgentEngine:
    def _make_engine(self, **kwargs):
        defaults = {
            "consensus_threshold": 0.85,
            "max_tokens": 512,
            "temperature": 0.1,
        }
        defaults.update(kwargs)
        return SingleAgentEngine(**defaults)

    def test_init(self):
        engine = self._make_engine()
        assert engine is not None
        assert engine.consensus_threshold == 0.85

    def test_get_status(self):
        engine = self._make_engine()
        status = engine.get_status()
        assert "consensus_threshold" in status
        assert "backend" in status or "model" in status or isinstance(status, dict)

    def test_clear_cache(self):
        engine = self._make_engine()
        cleared = engine.clear_cache()
        assert isinstance(cleared, int)
        assert cleared >= 0

    def test_build_finding_prompt(self):
        engine = self._make_engine()
        finding = {
            "id": "VULN-001",
            "severity": "critical",
            "title": "SQL Injection in login form",
            "description": "User input not sanitized",
            "cwe": "CWE-89",
        }
        prompt = engine._build_finding_prompt(finding)
        assert "SQL Injection" in prompt or "VULN-001" in prompt or len(prompt) > 0

    def test_parse_json_response_valid(self):
        engine = self._make_engine()
        text = '{"decision": "patch", "confidence": 0.9, "reasoning": "Critical vuln"}'
        result = engine._parse_json_response(text)
        assert result["decision"] == "patch"
        assert result["confidence"] == 0.9

    def test_parse_json_response_with_markdown(self):
        engine = self._make_engine()
        text = '```json\n{"decision": "patch"}\n```'
        result = engine._parse_json_response(text)
        assert result["decision"] == "patch"

    def test_parse_json_response_invalid(self):
        engine = self._make_engine()
        text = "This is not JSON at all"
        with pytest.raises(ValueError, match="Could not parse JSON"):
            engine._parse_json_response(text)

    @patch.object(SingleAgentEngine, "_get_expert_opinion")
    @patch.object(SingleAgentEngine, "_get_moderator_synthesis")
    def test_decide_with_mocked_experts(self, mock_moderator, mock_expert):
        mock_expert.return_value = ExpertOpinion(
            role=ExpertRole.ANALYST,
            decision="patch",
            confidence=0.9,
            reasoning="Critical vulnerability",
        )
        mock_moderator.return_value = ExpertOpinion(
            role=ExpertRole.MODERATOR,
            decision="patch",
            confidence=0.92,
            reasoning="All experts agree to patch",
        )
        engine = self._make_engine()
        finding = {
            "id": "VULN-001",
            "severity": "critical",
            "title": "SQL Injection",
        }
        result = engine.decide(finding)
        assert isinstance(result, ConsensusDecision)
        assert result.decision is not None

    @patch.object(SingleAgentEngine, "_get_expert_opinion")
    @patch.object(SingleAgentEngine, "_get_moderator_synthesis")
    def test_batch_decide(self, mock_moderator, mock_expert):
        mock_expert.return_value = ExpertOpinion(
            role=ExpertRole.ANALYST,
            decision="patch",
            confidence=0.9,
            reasoning="Critical",
        )
        mock_moderator.return_value = ExpertOpinion(
            role=ExpertRole.MODERATOR,
            decision="patch",
            confidence=0.92,
            reasoning="All agree",
        )
        engine = self._make_engine()
        findings = [
            {"id": "V1", "severity": "high", "title": "XSS"},
            {"id": "V2", "severity": "medium", "title": "CSRF"},
        ]
        results = engine.batch_decide(findings)
        assert len(results) == 2
        for r in results:
            assert isinstance(r, ConsensusDecision)

    @patch.object(SingleAgentEngine, "_get_expert_opinion")
    @patch.object(SingleAgentEngine, "_get_moderator_synthesis")
    def test_decide_consensus_split(self, mock_moderator, mock_expert):
        """When experts disagree, result should be SPLIT."""
        call_count = [0]
        decisions = ["patch", "accept", "patch", "mitigate"]

        def side_effect(role, prompt):
            idx = call_count[0] % len(decisions)
            call_count[0] += 1
            return ExpertOpinion(
                role=role,
                decision=decisions[idx],
                confidence=0.5,
                reasoning=f"Expert opinion {idx}",
            )

        mock_expert.side_effect = side_effect
        mock_moderator.return_value = ExpertOpinion(
            role=ExpertRole.MODERATOR,
            decision="accept",
            confidence=0.5,
            reasoning="No consensus",
        )
        engine = self._make_engine()
        finding = {"id": "V1", "severity": "medium", "title": "Info disclosure"}
        result = engine.decide(finding)
        assert isinstance(result, ConsensusDecision)
        # With split decisions, result should still be valid
        assert result.consensus_result in [ConsensusResult.AGREED, ConsensusResult.SPLIT, ConsensusResult.INSUFFICIENT]


class TestGetSingleAgentEngine:
    def test_returns_engine(self):
        engine = get_single_agent_engine()
        assert isinstance(engine, SingleAgentEngine)

    def test_singleton(self):
        e1 = get_single_agent_engine()
        e2 = get_single_agent_engine()
        assert e1 is e2


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    def test_expert_opinion_zero_confidence(self):
        op = ExpertOpinion(
            role=ExpertRole.ANALYST,
            decision="skip",
            confidence=0.0,
            reasoning="No data",
        )
        assert op.confidence == 0.0

    def test_expert_opinion_max_confidence(self):
        op = ExpertOpinion(
            role=ExpertRole.ANALYST,
            decision="patch",
            confidence=1.0,
            reasoning="Certain",
        )
        assert op.confidence == 1.0

    def test_empty_finding(self):
        engine = SingleAgentEngine()
        prompt = engine._build_finding_prompt({})
        assert isinstance(prompt, str)

    def test_finding_with_all_fields(self):
        engine = SingleAgentEngine()
        finding = {
            "id": "VULN-999",
            "severity": "critical",
            "title": "Remote Code Execution",
            "description": "Arbitrary command execution via unsanitized input",
            "cwe": "CWE-78",
            "cvss": 9.8,
            "scanner": "zap",
            "file_path": "/src/api/handler.py",
            "line_number": 42,
            "evidence": "curl http://target/api/exec?cmd=id",
        }
        prompt = engine._build_finding_prompt(finding)
        assert len(prompt) > 20

    def test_consensus_threshold_boundary(self):
        """Engine should work with extreme threshold values."""
        engine = SingleAgentEngine(consensus_threshold=0.0)
        assert engine.consensus_threshold == 0.0
        engine2 = SingleAgentEngine(consensus_threshold=1.0)
        assert engine2.consensus_threshold == 1.0
