"""Tests for CouncilPipelineAdapter — LLM Council Bridge for Brain Pipeline.

Validates the adapter's interface compatibility, error handling,
cost guarding, and session tracking without requiring real LLM providers.
"""

import pytest
from unittest.mock import MagicMock, patch
from core.council_pipeline_adapter import (
    CouncilPipelineAdapter,
    OpusCTOEscalation,
    ConsensusResult,
    EscalationRecord,
    create_consensus_engine_replacement,
)


@pytest.fixture
def adapter():
    """Create adapter with mocked council."""
    mock_council = MagicMock()
    mock_verdict = MagicMock()
    mock_verdict.action = "remediate_high"
    mock_verdict.confidence = 0.88
    mock_verdict.reasoning = "Critical vulnerability with active exploit"
    mock_verdict.member_votes = [MagicMock(action="remediate_high")] * 3
    mock_verdict.mitre_mappings = ["T1190"]
    mock_verdict.compliance_impact = {"SOC2": "CC6.1"}
    mock_verdict.escalated = False
    mock_verdict.escalation_reason = None
    mock_verdict.cost_usd = 0.001
    mock_verdict.latency_ms = 150
    mock_verdict.peer_review_changes = []
    mock_council.convene.return_value = mock_verdict
    mock_council.stats.return_value = {}

    return CouncilPipelineAdapter(council=mock_council)


@pytest.fixture
def escalation():
    return OpusCTOEscalation(max_escalations_per_hour=3)


class TestConsensusResult:
    """Test ConsensusResult dataclass."""

    def test_basic_creation(self):
        result = ConsensusResult(
            final_decision="block",
            method="council_verdict",
            confidence=0.95,
            reasoning="Test reasoning",
        )
        assert result.final_decision == "block"
        assert result.confidence == 0.95
        assert result.escalated is False
        assert result.cost_usd == 0.0

    def test_to_dict(self):
        result = ConsensusResult(
            final_decision="review",
            method="council_escalation",
            confidence=0.72,
            reasoning="Uncertain",
            council_session_id="abc123",
            escalated=True,
            escalation_reason="Low confidence",
            mitre_techniques=["T1190", "T1059"],
        )
        d = result.to_dict()
        assert d["final_decision"] == "review"
        assert d["escalated"] is True
        assert len(d["mitre_techniques"]) == 2
        assert isinstance(d["confidence"], float)

    def test_defaults(self):
        result = ConsensusResult(
            final_decision="allow",
            method="deterministic",
            confidence=1.0,
            reasoning="No issues",
        )
        assert result.providers_queried == 0
        assert result.air_gapped is False
        assert result.mitre_techniques == []
        assert result.compliance_concerns == []


class TestEscalationRecord:
    """Test EscalationRecord dataclass."""

    def test_auto_timestamp(self):
        record = EscalationRecord(
            timestamp="",
            finding_id="F001",
            council_session_id="S001",
            reason="Low confidence",
            cost_usd=0.02,
        )
        assert record.timestamp != ""  # Should auto-fill


class TestOpusCTOEscalation:
    """Test cost-guarded Opus escalation."""

    def test_can_escalate_initially(self, escalation):
        assert escalation.can_escalate() is True

    def test_budget_tracking(self, escalation):
        # Add 3 escalations (max is 3)
        for i in range(3):
            escalation.escalation_history.append(
                EscalationRecord(
                    timestamp="",
                    finding_id=f"F{i}",
                    council_session_id=f"S{i}",
                    reason="test",
                    cost_usd=0.02,
                )
            )
        assert escalation.can_escalate() is False

    def test_escalation_without_api_key(self, escalation):
        """Escalation should return conservative fallback without API key."""
        with patch.dict("os.environ", {}, clear=True):
            result = escalation.escalate_to_opus(
                finding={"title": "Test", "severity": "critical"},
                context={"service_name": "test"},
                council_session_id="s1",
                council_reasoning="test",
                reason="Low confidence",
            )
            assert result.final_decision in ("review", "allow")
            assert result.escalated is False  # Falls back


class TestCouncilPipelineAdapter:
    """Test the main adapter interface."""

    def test_analyse_returns_dict(self, adapter):
        result = adapter.analyse(
            prompt="Test prompt",
            context={"org_id": "test"},
            findings=[
                {"title": "CVE-2024-1234", "risk_score": 0.8, "severity": "critical"},
            ],
        )
        assert isinstance(result, dict)
        assert "analyzed" in result
        assert "decision" in result
        assert "method" in result

    def test_analyse_filters_low_risk(self, adapter):
        result = adapter.analyse(
            prompt="Test",
            findings=[
                {"title": "Low risk", "risk_score": 0.3, "severity": "low"},
            ],
        )
        assert result["analyzed"] == 0
        assert result["reason"] == "no critical findings"

    def test_analyse_high_risk_findings(self, adapter):
        result = adapter.analyse(
            prompt="Test",
            context={"org_id": "test_org"},
            findings=[
                {"title": "RCE", "risk_score": 0.95, "severity": "critical"},
                {"title": "XSS", "risk_score": 0.75, "severity": "high"},
            ],
        )
        assert result["analyzed"] == 2
        assert result["decision"] == "remediate_high"
        assert result["method"] == "council_verdict"

    def test_analyse_empty_findings(self, adapter):
        result = adapter.analyse(prompt="Test", findings=[])
        assert result["analyzed"] == 0

    def test_analyse_no_findings_key(self, adapter):
        result = adapter.analyse(prompt="Test", context={})
        assert result["analyzed"] == 0

    def test_session_history_tracking(self, adapter):
        adapter.analyse(
            prompt="Test",
            findings=[{"title": "F1", "risk_score": 0.9, "severity": "critical"}],
        )
        assert len(adapter._session_history) == 1
        assert adapter._session_history[0]["decision"] == "remediate_high"

    def test_council_stats(self, adapter):
        adapter.analyse(
            prompt="Test",
            findings=[{"title": "F1", "risk_score": 0.9, "severity": "critical"}],
        )
        stats = adapter.get_council_stats()
        assert stats["total_sessions"] == 1
        assert stats["total_findings_analyzed"] == 1
        assert stats["escalation_count"] == 0

    def test_multiple_sessions_stats(self, adapter):
        for i in range(3):
            adapter.analyse(
                prompt=f"Test {i}",
                findings=[{"title": f"F{i}", "risk_score": 0.85, "severity": "critical"}],
            )
        stats = adapter.get_council_stats()
        assert stats["total_sessions"] == 3

    def test_analyse_error_handling(self):
        """Test graceful fallback when council fails."""
        mock_council = MagicMock()
        mock_council.convene.side_effect = RuntimeError("Council unavailable")

        adapter = CouncilPipelineAdapter(council=mock_council)
        result = adapter.analyse(
            prompt="Test",
            findings=[{"title": "F1", "risk_score": 0.9, "severity": "critical"}],
        )
        assert result["decision"] == "review"
        assert result["method"] == "fallback"


class TestFactoryFunction:
    """Test create_consensus_engine_replacement."""

    def test_factory_creates_adapter(self):
        adapter = create_consensus_engine_replacement()
        assert isinstance(adapter, CouncilPipelineAdapter)

    def test_factory_with_custom_council(self):
        mock = MagicMock()
        adapter = create_consensus_engine_replacement(council=mock)
        assert adapter._council is mock

    def test_factory_returns_new_instance(self):
        a1 = create_consensus_engine_replacement()
        a2 = create_consensus_engine_replacement()
        assert a1 is not a2


class TestAnalystFeedback:
    """Test analyst feedback recording."""

    def test_feedback_without_memory(self, adapter):
        """Should return empty string when memory unavailable."""
        result = adapter.record_analyst_feedback(
            finding_id="F001",
            analyst_id="analyst@test.com",
            original_action="review",
            new_action="false_positive",
            reason="Known FP",
            org_id="test",
        )
        # Without real memory store, should gracefully handle
        assert isinstance(result, str)
