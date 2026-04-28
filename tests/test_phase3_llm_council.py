"""
Comprehensive tests for Phase 3 of the ALDECI LLM Council system.

Tests cover:
- LLM Council Engine (3-stage decision synthesis)
- Decision Memory persistence and learning
- Council Pipeline Adapter (brain_pipeline integration)
- Mock LLM providers (deterministic, no real API calls)

Run with: python -m pytest tests/test_phase3_llm_council.py -v --timeout=15
"""

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import pytest

# Add suite-core to path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.decision_memory import (
    AccuracyStats,
    DecisionFeedbackLoop,
    DecisionMemoryStore,
    DecisionRecord,
)
from core.llm_council import (
    CouncilFactory,
    CouncilMember,
    CouncilVerdict,
    LLMCouncilEngine,
    MemberAnalysis,
    MemberVote,
    PositionChange,
)
from core.llm_providers import BaseLLMProvider, LLMResponse
from core.council_pipeline_adapter import (
    CouncilPipelineAdapter,
    ConsensusResult,
    OpusCTOEscalation,
    create_consensus_engine_replacement,
)


# ============================================================================
# Mock LLM Provider
# ============================================================================


class MockLLMProvider(BaseLLMProvider):
    """Mock LLM provider that returns deterministic, configurable responses."""

    def __init__(
        self,
        name: str,
        *,
        default_action: str = "remediate_high",
        default_confidence: float = 0.85,
        mitre_techniques: Optional[List[str]] = None,
        compliance_concerns: Optional[List[str]] = None,
        should_fail: bool = False,
    ):
        super().__init__(name)
        self.default_action = default_action
        self.default_confidence = default_confidence
        self.mitre_techniques = mitre_techniques or ["T1110", "T1190"]
        self.compliance_concerns = compliance_concerns or ["SOC2", "HIPAA"]
        self.should_fail = should_fail
        self.call_count = 0

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Return a mock response."""
        self.call_count += 1

        if self.should_fail:
            raise RuntimeError(f"Mock provider {self.name} configured to fail")

        return LLMResponse(
            recommended_action=self.default_action,
            confidence=self.default_confidence,
            reasoning=f"Mock analysis from {self.name}: {default_reasoning}",
            mitre_techniques=self.mitre_techniques,
            compliance_concerns=self.compliance_concerns,
            attack_vectors=["Network exploit", "Local privilege escalation"],
            metadata={
                "mode": "mock",
                "provider": self.name,
                "call_count": self.call_count,
            },
        )


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db_path(tmp_path):
    """Temporary database path for tests."""
    return str(tmp_path / "test_memory.db")


@pytest.fixture
def mock_provider_list():
    """List of mock providers for council."""
    return [
        MockLLMProvider("analyst-1", default_action="remediate_critical", default_confidence=0.9),
        MockLLMProvider("analyst-2", default_action="remediate_high", default_confidence=0.85),
        MockLLMProvider("analyst-3", default_action="remediate_high", default_confidence=0.80),
    ]


@pytest.fixture
def council_members(mock_provider_list):
    """Create council members from mock providers."""
    return [
        CouncilMember(
            provider=mock_provider_list[0],
            expertise="vulnerability_assessment",
            weight=1.0,
            name="Analyst 1",
        ),
        CouncilMember(
            provider=mock_provider_list[1],
            expertise="threat_modeling",
            weight=0.95,
            name="Analyst 2",
        ),
        CouncilMember(
            provider=mock_provider_list[2],
            expertise="compliance_mapping",
            weight=0.9,
            name="Analyst 3",
        ),
    ]


@pytest.fixture
def chairman_provider():
    """Chairman provider for council synthesis."""
    return MockLLMProvider(
        "chairman",
        default_action="remediate_high",
        default_confidence=0.88,
    )


@pytest.fixture
def test_finding():
    """Sample security finding."""
    return {
        "id": "vuln-001",
        "title": "SQL Injection in Login Form",
        "severity": "critical",
        "cve_id": "CVE-2024-1234",
        "risk_score": 0.92,
        "description": "SQL injection vulnerability in user authentication",
    }


@pytest.fixture
def test_context():
    """Sample context for finding analysis."""
    return {
        "service_name": "auth-service",
        "environment": "production",
        "org_id": "acme-corp",
    }


@pytest.fixture
def decision_memory_store(tmp_db_path):
    """Initialize a decision memory store."""
    return DecisionMemoryStore(db_path=tmp_db_path)


@pytest.fixture
def council(council_members, chairman_provider):
    """Initialize an LLM council."""
    return LLMCouncilEngine(
        members=council_members,
        chairman=chairman_provider,
        confidence_threshold=0.7,
        max_disagreement=2,
        max_workers=2,
    )


# ============================================================================
# CouncilMember Tests
# ============================================================================


class TestCouncilMember:
    """Test CouncilMember creation and validation."""

    def test_council_member_creation(self, mock_provider_list):
        """Test CouncilMember can be created with provider."""
        member = CouncilMember(
            provider=mock_provider_list[0],
            expertise="vulnerability_assessment",
            weight=1.0,
        )
        assert member.provider is mock_provider_list[0]
        assert member.expertise == "vulnerability_assessment"
        assert member.weight == 1.0
        assert member.name == "analyst-1"

    def test_council_member_custom_name(self, mock_provider_list):
        """Test CouncilMember custom name."""
        member = CouncilMember(
            provider=mock_provider_list[0],
            expertise="threat_modeling",
            name="Custom Name",
        )
        assert member.name == "Custom Name"

    def test_council_member_default_weight(self, mock_provider_list):
        """Test CouncilMember defaults weight to 1.0."""
        member = CouncilMember(
            provider=mock_provider_list[0],
            expertise="code_analysis",
        )
        assert member.weight == 1.0


# ============================================================================
# Council Stage Tests
# ============================================================================


class TestCouncilStage1:
    """Test Stage 1: Independent Analysis."""

    def test_stage1_independent_analysis(self, council, test_finding, test_context):
        """Test that stage 1 runs independent analysis for all members."""
        analyses = council._stage_independent_analysis(test_finding, test_context)

        assert len(analyses) == 3
        for analysis in analyses:
            assert analysis.stage == "1_independent"
            assert analysis.position in [
                "remediate_critical",
                "remediate_high",
            ]
            assert 0 <= analysis.confidence <= 1
            assert analysis.reasoning
            assert "T1110" in analysis.mitre_mappings or len(analysis.mitre_mappings) > 0

    def test_stage1_member_failure_handling(self, council_members, test_finding, test_context):
        """Test that stage 1 handles member failures gracefully."""
        failing_member = CouncilMember(
            provider=MockLLMProvider("failing", should_fail=True),
            expertise="test",
        )
        council = LLMCouncilEngine(
            members=council_members[:2] + [failing_member],
            chairman=council_members[0].provider,
        )

        analyses = council._stage_independent_analysis(test_finding, test_context)
        assert len(analyses) == 2  # Only successful members


class TestCouncilStage2:
    """Test Stage 2: Anonymous Peer Review."""

    def test_stage2_peer_review(self, council, test_finding, test_context):
        """Test that stage 2 allows members to review and potentially change positions."""
        stage1_analyses = council._stage_independent_analysis(
            test_finding, test_context
        )
        stage2_analyses = council._stage_peer_review(
            stage1_analyses, test_finding, test_context
        )

        assert len(stage2_analyses) == len(stage1_analyses)
        for analysis in stage2_analyses:
            assert analysis.stage == "2_peer_review"
            assert analysis.position  # Should have a position

    def test_stage2_anonymous_summary(self, council, council_members):
        """Test that peer summary is anonymous."""
        analyses = [
            MemberAnalysis(
                member_name="Alice",
                expertise="vuln_assessment",
                stage="1_independent",
                position="remediate_critical",
                confidence=0.9,
                reasoning="High risk, actively exploited",
            ),
            MemberAnalysis(
                member_name="Bob",
                expertise="threat_modeling",
                stage="1_independent",
                position="remediate_high",
                confidence=0.8,
                reasoning="Moderate risk, requires investigation",
            ),
        ]

        summary = council._build_peer_summary(analyses)
        assert "Alice" not in summary
        assert "Bob" not in summary
        assert "Member 1" in summary
        assert "Member 2" in summary
        assert "remediate_critical" in summary
        assert "remediate_high" in summary


class TestCouncilStage3:
    """Test Stage 3: Chairman Synthesis."""

    def test_stage3_chairman_synthesis(self, council, test_finding, test_context):
        """Test that stage 3 synthesizes all analyses into final verdict."""
        stage1 = council._stage_independent_analysis(test_finding, test_context)
        stage2 = council._stage_peer_review(stage1, test_finding, test_context)

        verdict = council._stage_chairman_synthesis(stage1, stage2, test_finding, test_context)

        assert isinstance(verdict, CouncilVerdict)
        assert verdict.action in [
            "remediate_critical",
            "remediate_high",
            "accept_risk",
            "defer",
            "investigate",
            "false_positive",
        ]
        assert 0 <= verdict.confidence <= 1
        assert verdict.reasoning
        assert len(verdict.member_votes) == 3


# ============================================================================
# Full Council Convene Tests
# ============================================================================


class TestCouncilConvene:
    """Test full council convocation end-to-end."""

    def test_council_convene_full_flow(self, council, test_finding, test_context):
        """Test complete council convocation."""
        verdict = council.convene(test_finding, test_context)

        assert isinstance(verdict, CouncilVerdict)
        assert verdict.action
        assert 0 <= verdict.confidence <= 1
        assert verdict.reasoning
        assert verdict.latency_ms > 0
        assert len(verdict.member_votes) == 3
        assert verdict in council.history

    def test_council_convene_low_confidence_detection(self, council_members):
        """Test that council detects low confidence."""
        low_conf_provider = MockLLMProvider(
            "low-conf",
            default_confidence=0.6,
        )
        council = LLMCouncilEngine(
            members=[
                CouncilMember(
                    provider=low_conf_provider,
                    expertise="test",
                ),
            ],
            chairman=low_conf_provider,
            confidence_threshold=0.7,
        )

        verdict = council.convene(
            {"title": "Test", "severity": "high", "risk_score": 0.8},
            {},
        )
        # Should detect low confidence
        assert verdict.confidence < 0.7

    def test_council_statistics(self, council, test_finding, test_context):
        """Test council maintains statistics."""
        council.convene(test_finding, test_context)
        council.convene(test_finding, test_context)

        stats = council.stats()
        assert stats["total_convocations"] == 2
        assert stats["average_latency_ms"] > 0
        assert "action_distribution" in stats


# ============================================================================
# Council Escalation Tests
# ============================================================================


class TestCouncilEscalation:
    """Test escalation detection and handling."""

    def test_escalation_on_low_confidence(self, council):
        """Test escalation is triggered on low confidence."""
        verdict = CouncilVerdict(
            action="accept_risk",
            confidence=0.65,  # Below 0.7 threshold
            reasoning="Low confidence verdict",
            member_votes=[
                MemberVote("A", "test", "accept_risk", 0.65, 1.0),
                MemberVote("B", "test", "remediate_high", 0.8, 1.0),
            ],
        )

        assert council.should_escalate(verdict) is True

    def test_escalation_on_high_disagreement(self, council):
        """Test escalation on high disagreement."""
        verdict = CouncilVerdict(
            action="remediate_critical",
            confidence=0.85,
            reasoning="Some disagreement",
            member_votes=[
                MemberVote("A", "test", "remediate_critical", 0.9, 1.0),
                MemberVote("B", "test", "accept_risk", 0.8, 1.0),
                MemberVote("C", "test", "defer", 0.75, 1.0),
                MemberVote("D", "test", "investigate", 0.7, 1.0),
            ],
        )

        # 3 dissenters (B, C, D) > max_disagreement (2)
        assert council.should_escalate(verdict) is True

    def test_no_escalation_on_consensus(self, council):
        """Test no escalation when consensus is strong."""
        verdict = CouncilVerdict(
            action="remediate_critical",
            confidence=0.92,
            reasoning="Strong consensus",
            member_votes=[
                MemberVote("A", "test", "remediate_critical", 0.95, 1.0),
                MemberVote("B", "test", "remediate_critical", 0.90, 1.0),
                MemberVote("C", "test", "remediate_critical", 0.89, 1.0),
            ],
        )

        assert council.should_escalate(verdict) is False


# ============================================================================
# Council Factory Tests
# ============================================================================


class TestCouncilFactory:
    """Test CouncilFactory preset configurations."""

    def test_factory_create_security_council(self):
        """Test factory creates security-focused council.

        Uses FIXOPS_COUNCIL_PRESET=full to test the legacy 5-member path.
        In normal deployment (auto preset + free-tier keys) the council returns
        2 real members (mulerouter+openrouter) — tested in test_llm_council_real_2member.py.
        """
        import os
        old_preset = os.environ.get("FIXOPS_COUNCIL_PRESET")
        os.environ["FIXOPS_COUNCIL_PRESET"] = "full"
        try:
            factory = CouncilFactory()
            council = factory.create_security_council()

            assert isinstance(council, LLMCouncilEngine)
            assert len(council.members) == 5
            assert council.confidence_threshold == 0.75
            assert any(m.expertise == "vulnerability_assessment" for m in council.members)
        finally:
            if old_preset is None:
                os.environ.pop("FIXOPS_COUNCIL_PRESET", None)
            else:
                os.environ["FIXOPS_COUNCIL_PRESET"] = old_preset

    def test_factory_create_compliance_council(self):
        """Test factory creates compliance-focused council."""
        factory = CouncilFactory()
        council = factory.create_compliance_council()

        assert isinstance(council, LLMCouncilEngine)
        assert len(council.members) == 5
        assert council.confidence_threshold == 0.8
        assert any(m.expertise == "compliance_mapping" for m in council.members)

    def test_factory_custom_thresholds(self):
        """Test factory accepts custom thresholds."""
        factory = CouncilFactory()
        council = factory.create_security_council(
            confidence_threshold=0.9,
            max_disagreement=1,
        )

        assert council.confidence_threshold == 0.9
        assert council.max_disagreement == 1

    def test_deepseek_in_security_council(self):
        """Test DeepSeek R1 is included in the full security council (preset=full)."""
        import os
        old_preset = os.environ.get("FIXOPS_COUNCIL_PRESET")
        os.environ["FIXOPS_COUNCIL_PRESET"] = "full"
        try:
            factory = CouncilFactory()
            council = factory.create_security_council()

            assert len(council.members) == 5
            deepseek_members = [
                m for m in council.members
                if "DeepSeek" in (m.name or "") or m.expertise == "vulnerability_research"
            ]
            assert len(deepseek_members) == 1
            assert deepseek_members[0].name == "Vulnerability Researcher (DeepSeek R1)"
            assert deepseek_members[0].weight == 0.9
            assert council.max_workers == 5
        finally:
            if old_preset is None:
                os.environ.pop("FIXOPS_COUNCIL_PRESET", None)
            else:
                os.environ["FIXOPS_COUNCIL_PRESET"] = old_preset

    def test_deepseek_in_full_council(self):
        """Test DeepSeek R1 is included in the full council with correct position and weight."""
        factory = CouncilFactory()
        council = factory.create_full_council()

        provider_names = [m.provider.name for m in council.members]
        assert "deepseek_r1" in provider_names

        deepseek_member = next(
            m for m in council.members if m.provider.name == "deepseek_r1"
        )
        assert deepseek_member.expertise == "vulnerability_research"
        assert deepseek_member.weight == 0.92

        # DeepSeek should be 3rd (index 2), after openai and anthropic
        assert provider_names.index("deepseek_r1") == 2

    def test_deepseek_in_compliance_council(self):
        """Test DeepSeek R1 is included in the compliance council."""
        factory = CouncilFactory()
        council = factory.create_compliance_council()

        assert len(council.members) == 5
        deepseek_members = [
            m for m in council.members
            if "DeepSeek" in (m.name or "")
        ]
        assert len(deepseek_members) == 1
        assert deepseek_members[0].name == "Regulatory Analyst (DeepSeek R1)"
        assert deepseek_members[0].expertise == "regulatory_analysis"
        assert deepseek_members[0].weight == 0.88

    def test_deepseek_in_threat_council(self):
        """Test DeepSeek R1 is included in the threat council."""
        factory = CouncilFactory()
        council = factory.create_threat_council()

        assert len(council.members) == 5
        deepseek_members = [
            m for m in council.members
            if "DeepSeek" in (m.name or "")
        ]
        assert len(deepseek_members) == 1
        assert deepseek_members[0].name == "Attack Chain Analyst (DeepSeek R1)"
        assert deepseek_members[0].expertise == "attack_chain_analysis"
        assert deepseek_members[0].weight == 0.92


# ============================================================================
# DeepSeek Provider Config Tests
# ============================================================================


class TestDeepSeekProviderConfig:
    """Test DeepSeek R1 provider registration and configuration."""

    def test_deepseek_provider_config(self):
        """Test deepseek provider is registered in LLMProviderManager with correct config."""
        from core.llm_providers import LLMProviderManager, OpenRouterProvider

        manager = LLMProviderManager()
        provider = manager.get_provider("deepseek")

        assert isinstance(provider, OpenRouterProvider)
        assert provider.name == "deepseek_r1"
        assert provider.model == "deepseek/deepseek-r1:free"
        assert provider.style == "analyst"
        assert "reasoning" in provider.focus
        assert "code_analysis" in provider.focus
        assert "vulnerability_research" in provider.focus

    def test_deepseek_api_key_envs(self):
        """Test deepseek provider reads from OPENROUTER_API_KEY and MULEROUTER_API_KEY."""
        from core.llm_providers import LLMProviderManager

        manager = LLMProviderManager()
        provider = manager.get_provider("deepseek")

        assert "OPENROUTER_API_KEY" in provider.api_key_envs
        assert "MULEROUTER_API_KEY" in provider.api_key_envs

    def test_deepseek_r1_in_free_models_list(self):
        """Test deepseek/deepseek-r1:free is in the OPENROUTER_FREE_MODELS list."""
        from core.llm_providers import OPENROUTER_FREE_MODELS

        assert "deepseek/deepseek-r1:free" in OPENROUTER_FREE_MODELS


# ============================================================================
# CouncilVerdict Serialization Tests
# ============================================================================


class TestCouncilVerdictSerialization:
    """Test CouncilVerdict serialization."""

    def test_verdict_to_dict(self):
        """Test verdict serialization to dict."""
        verdict = CouncilVerdict(
            action="remediate_critical",
            confidence=0.87,
            reasoning="SQL injection with active exploit",
            mitre_mappings=["T1110", "T1190"],
            compliance_impact={"SOC2": "to_review", "HIPAA": "to_review"},
            member_votes=[
                MemberVote("A", "vuln", "remediate_critical", 0.9, 1.0),
                MemberVote("B", "threat", "remediate_critical", 0.85, 0.95),
            ],
            peer_review_changes=[
                PositionChange("A", "remediate_high", "remediate_critical", "Peer input")
            ],
            escalated=False,
            cost_usd=0.05,
            latency_ms=1250.5,
        )

        d = verdict.to_dict()

        assert d["action"] == "remediate_critical"
        assert d["confidence"] == 0.87
        assert len(d["member_votes"]) == 2
        assert len(d["peer_review_changes"]) == 1
        assert d["escalated"] is False
        assert d["cost_usd"] == 0.05
        assert d["latency_ms"] == 1250.5


# ============================================================================
# Decision Memory Tests
# ============================================================================


class TestDecisionRecord:
    """Test DecisionRecord creation and serialization."""

    def test_decision_record_creation(self):
        """Test DecisionRecord can be created."""
        record = DecisionRecord(
            finding_id="vuln-123",
            finding_hash="abc123def456",
            action="remediate_critical",
            confidence=0.92,
            reasoning="High CVSS + exploited in wild",
            org_id="acme-corp",
        )

        assert record.finding_id == "vuln-123"
        assert record.action == "remediate_critical"
        assert record.confidence == 0.92
        assert record.record_id  # Should be auto-generated

    def test_decision_record_to_dict(self):
        """Test DecisionRecord serialization."""
        record = DecisionRecord(
            finding_id="vuln-123",
            action="accept_risk",
            confidence=0.65,
            mitre_techniques=["T1110"],
            compliance_impact=["SOC2"],
            org_id="acme-corp",
        )

        d = record.to_dict()

        assert d["finding_id"] == "vuln-123"
        assert d["action"] == "accept_risk"
        assert d["confidence"] == 0.65
        assert isinstance(d["mitre_techniques"], list)
        assert isinstance(d["compliance_impact"], list)

    def test_decision_record_from_dict_roundtrip(self):
        """Test DecisionRecord round-trip serialization."""
        original = DecisionRecord(
            finding_id="vuln-456",
            action="investigate",
            confidence=0.75,
            mitre_techniques=["T1234", "T5678"],
            compliance_impact=["HIPAA"],
            org_id="corp-x",
            metadata={"notes": "test"},
        )

        d = original.to_dict()
        restored = DecisionRecord.from_dict(d)

        assert restored.finding_id == original.finding_id
        assert restored.action == original.action
        assert restored.confidence == original.confidence
        assert restored.mitre_techniques == original.mitre_techniques
        assert restored.compliance_impact == original.compliance_impact


class TestDecisionMemoryStore:
    """Test DecisionMemoryStore persistence."""

    def test_store_record(self, decision_memory_store):
        """Test recording a decision."""
        record = DecisionRecord(
            finding_id="vuln-001",
            finding_hash="hash001",
            action="remediate_critical",
            confidence=0.92,
            org_id="acme",
        )

        record_id = decision_memory_store.record(record)

        assert record_id == record.record_id

    def test_store_get_record(self, decision_memory_store):
        """Test retrieving a recorded decision."""
        record = DecisionRecord(
            finding_id="vuln-002",
            finding_hash="hash002",
            action="remediate_high",
            confidence=0.85,
            org_id="acme",
        )

        record_id = decision_memory_store.record(record)
        retrieved = decision_memory_store.get(record_id)

        assert retrieved is not None
        assert retrieved.finding_id == "vuln-002"
        assert retrieved.action == "remediate_high"

    def test_store_find_similar(self, decision_memory_store):
        """Test finding similar decisions by hash."""
        record1 = DecisionRecord(
            finding_id="vuln-101",
            finding_hash="hash-similar",
            action="remediate_critical",
            org_id="acme",
        )
        record2 = DecisionRecord(
            finding_id="vuln-102",
            finding_hash="hash-similar",
            action="remediate_critical",
            org_id="acme",
        )

        decision_memory_store.record(record1)
        decision_memory_store.record(record2)

        similar = decision_memory_store.find_similar("hash-similar", "acme", limit=5)

        assert len(similar) == 2
        assert all(r.finding_hash == "hash-similar" for r in similar)

    def test_store_find_by_finding(self, decision_memory_store):
        """Test finding all decisions for a finding."""
        for i in range(3):
            record = DecisionRecord(
                finding_id="vuln-200",
                finding_hash=f"hash-{i}",
                action="remediate_high",
                org_id="acme",
            )
            decision_memory_store.record(record)

        decisions = decision_memory_store.find_by_finding("vuln-200")

        assert len(decisions) == 3
        assert all(d.finding_id == "vuln-200" for d in decisions)

    def test_store_search(self, decision_memory_store):
        """Test searching decisions with filters."""
        for action in ["remediate_critical", "remediate_high", "accept_risk"]:
            record = DecisionRecord(
                finding_id=f"vuln-{action}",
                action=action,
                org_id="acme",
            )
            decision_memory_store.record(record)

        results = decision_memory_store.search("acme", action="remediate_critical")

        assert len(results) == 1
        assert results[0].action == "remediate_critical"

    def test_store_count(self, decision_memory_store):
        """Test counting decisions."""
        for i in range(5):
            record = DecisionRecord(
                finding_id=f"vuln-{i}",
                action="remediate_high",
                org_id="acme",
            )
            decision_memory_store.record(record)

        count = decision_memory_store.count("acme")

        assert count == 5

    def test_store_multi_tenant_isolation(self, decision_memory_store):
        """Test that org_id filters records (multi-tenant isolation)."""
        record_acme = DecisionRecord(
            finding_id="vuln-acme",
            action="remediate_critical",
            org_id="acme-corp",
        )
        record_other = DecisionRecord(
            finding_id="vuln-other",
            action="accept_risk",
            org_id="other-corp",
        )

        decision_memory_store.record(record_acme)
        decision_memory_store.record(record_other)

        acme_count = decision_memory_store.count("acme-corp")
        other_count = decision_memory_store.count("other-corp")

        assert acme_count == 1
        assert other_count == 1


class TestAccuracyStats:
    """Test AccuracyStats computation."""

    def test_accuracy_stats_creation(self):
        """Test AccuracyStats dataclass."""
        stats = AccuracyStats(
            total_decisions=100,
            analyst_overrides=5,
            override_rate=0.05,
            false_positive_rate=0.02,
            action_accuracy={"remediate_critical": 0.98, "accept_risk": 0.88},
            most_overridden_action="accept_risk",
        )

        assert stats.total_decisions == 100
        assert stats.analyst_overrides == 5
        assert stats.override_rate == 0.05

    def test_accuracy_stats_to_dict(self):
        """Test AccuracyStats serialization."""
        stats = AccuracyStats(
            total_decisions=100,
            analyst_overrides=8,
            override_rate=0.08,
            false_positive_rate=0.03,
            action_accuracy={"remediate_critical": 0.95, "accept_risk": 0.85},
        )

        d = stats.to_dict()

        assert d["total_decisions"] == 100
        assert d["analyst_overrides"] == 8
        assert isinstance(d["action_accuracy"], dict)

    def test_store_get_accuracy_stats(self, decision_memory_store):
        """Test computing accuracy stats from store."""
        # Record council verdicts
        for i in range(10):
            record = DecisionRecord(
                finding_id=f"vuln-{i}",
                action="remediate_critical" if i % 2 == 0 else "remediate_high",
                decision_type="council_verdict",
                org_id="acme",
            )
            decision_memory_store.record(record)

        # Record some overrides
        for i in range(2):
            record = DecisionRecord(
                finding_id=f"vuln-{i}",
                action="accept_risk",
                decision_type="analyst_override",
                org_id="acme",
                metadata={"original_action": "remediate_critical"},
            )
            decision_memory_store.record(record)

        stats = decision_memory_store.get_accuracy_stats("acme")

        assert stats.total_decisions == 12
        assert stats.analyst_overrides == 2
        assert stats.override_rate > 0


class TestDecisionFeedbackLoop:
    """Test DecisionFeedbackLoop for analyst learning."""

    def test_record_override(self, decision_memory_store):
        """Test recording an analyst override."""
        loop = DecisionFeedbackLoop(decision_memory_store)

        record_id = loop.record_override(
            finding_id="vuln-123",
            original_action="accept_risk",
            new_action="remediate_critical",
            analyst_id="alice@acme.com",
            reason="Exploit discovered in the wild",
            org_id="acme",
        )

        assert record_id
        retrieved = decision_memory_store.get(record_id)
        assert retrieved.action == "remediate_critical"
        assert retrieved.decision_type == "analyst_override"

    def test_record_false_positive(self, decision_memory_store):
        """Test recording a false positive."""
        loop = DecisionFeedbackLoop(decision_memory_store)

        record_id = loop.record_false_positive(
            finding_id="vuln-456",
            analyst_id="bob@acme.com",
            reason="Not exploitable in our environment",
            org_id="acme",
        )

        assert record_id
        retrieved = decision_memory_store.get(record_id)
        assert retrieved.action == "false_positive"

    def test_get_learning_data(self, decision_memory_store):
        """Test exporting training data for learning."""
        loop = DecisionFeedbackLoop(decision_memory_store)

        # Record overrides
        for i in range(3):
            loop.record_override(
                finding_id=f"vuln-{i}",
                original_action="accept_risk",
                new_action="remediate_critical",
                analyst_id="alice@acme.com",
                reason="Override reason",
                org_id="acme",
            )

        learning_data = loop.get_learning_data("acme")

        assert len(learning_data) == 3
        assert all("original_action" in d for d in learning_data)
        assert all("corrected_action" in d for d in learning_data)


# ============================================================================
# Council Pipeline Adapter Tests
# ============================================================================


class TestOpusCTOEscalation:
    """Test OpusCTOEscalation cost guarding."""

    def test_escalation_cost_guard_available(self):
        """Test escalation budget tracking."""
        escalation = OpusCTOEscalation(max_escalations_per_hour=10)

        assert escalation.can_escalate() is True

    def test_escalation_budget_exhaustion(self):
        """Test escalation budget exhaustion."""
        escalation = OpusCTOEscalation(max_escalations_per_hour=1)

        # First escalation should succeed
        from core.council_pipeline_adapter import EscalationRecord

        escalation.escalation_history.append(
            EscalationRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                finding_id="vuln-1",
                council_session_id="session-1",
                reason="Low confidence",
                cost_usd=0.02,
            )
        )

        # Second escalation should fail (budget exhausted)
        assert escalation.can_escalate() is False


class TestCouncilPipelineAdapter:
    """Test CouncilPipelineAdapter integration."""

    def test_adapter_creation(self):
        """Test adapter can be created."""
        adapter = CouncilPipelineAdapter()

        assert adapter is not None
        assert hasattr(adapter, "analyse")

    def test_adapter_analyse_returns_compatible_format(self, council, tmp_db_path):
        """Test adapter returns brain_pipeline-compatible format."""
        memory_store = DecisionMemoryStore(db_path=tmp_db_path)
        adapter = CouncilPipelineAdapter(council=council, memory_store=memory_store)

        findings = [
            {
                "id": "vuln-1",
                "title": "SQL Injection",
                "severity": "critical",
                "risk_score": 0.95,
            }
        ]

        result = adapter.analyse(
            prompt="Analyze these findings",
            context={"org_id": "test-org"},
            findings=findings,
        )

        assert isinstance(result, dict)
        assert "analyzed" in result
        assert "decision" in result
        assert "method" in result
        assert "confidence" in result
        assert "session_id" in result

    def test_adapter_analyst_feedback(self, council, tmp_db_path):
        """Test recording analyst feedback."""
        memory_store = DecisionMemoryStore(db_path=tmp_db_path)
        adapter = CouncilPipelineAdapter(council=council, memory_store=memory_store)

        record_id = adapter.record_analyst_feedback(
            finding_id="vuln-123",
            analyst_id="alice@test.com",
            original_action="accept_risk",
            new_action="remediate_critical",
            reason="Exploit discovered",
            org_id="test-org",
        )

        assert record_id

    def test_adapter_get_council_stats(self, council, tmp_db_path):
        """Test retrieving council stats."""
        memory_store = DecisionMemoryStore(db_path=tmp_db_path)
        adapter = CouncilPipelineAdapter(council=council, memory_store=memory_store)

        # Run some analyses
        findings = [
            {
                "id": "vuln-1",
                "title": "Test",
                "severity": "high",
                "risk_score": 0.8,
            }
        ]
        adapter.analyse(
            prompt="Test",
            context={"org_id": "test-org"},
            findings=findings,
        )

        stats = adapter.get_council_stats()

        assert "total_sessions" in stats
        assert "total_findings_analyzed" in stats
        assert "escalation_rate" in stats


class TestConsensusEngineReplacement:
    """Test create_consensus_engine_replacement factory."""

    def test_factory_creates_adapter(self):
        """Test factory creates CouncilPipelineAdapter."""
        adapter = create_consensus_engine_replacement()

        assert isinstance(adapter, CouncilPipelineAdapter)
        assert hasattr(adapter, "analyse")


# ============================================================================
# Integration Tests
# ============================================================================


class TestFullIntegration:
    """End-to-end integration tests."""

    def test_full_flow_council_to_memory_to_stats(self, council_members, tmp_db_path):
        """Test complete flow: council -> memory -> stats."""
        # Create council
        chairman = council_members[0].provider
        council = LLMCouncilEngine(
            members=council_members,
            chairman=chairman,
        )

        # Create memory and feedback
        memory_store = DecisionMemoryStore(db_path=tmp_db_path)
        feedback_loop = DecisionFeedbackLoop(memory_store)

        # Run council analysis
        finding = {
            "title": "Test Vuln",
            "severity": "critical",
            "risk_score": 0.9,
        }
        verdict = council.convene(finding, {})

        # Record in memory
        from core.decision_memory import _sha256_finding

        finding_hash = _sha256_finding(json.dumps(finding))
        record = DecisionRecord(
            finding_id="test-1",
            finding_hash=finding_hash,
            action=verdict.action,
            confidence=verdict.confidence,
            org_id="test-org",
        )
        memory_store.record(record)

        # Record override
        feedback_loop.record_override(
            finding_id="test-1",
            original_action=verdict.action,
            new_action="accept_risk",
            analyst_id="tester@test.com",
            reason="Testing",
            org_id="test-org",
        )

        # Check stats
        stats = memory_store.get_accuracy_stats("test-org")
        assert stats.total_decisions == 2
        assert stats.analyst_overrides == 1

    def test_adapter_full_pipeline(self, council_members, tmp_db_path):
        """Test full adapter pipeline integration."""
        # Setup council and adapter
        chairman = council_members[0].provider
        council = LLMCouncilEngine(
            members=council_members,
            chairman=chairman,
        )
        memory_store = DecisionMemoryStore(db_path=tmp_db_path)
        adapter = CouncilPipelineAdapter(council=council, memory_store=memory_store)

        # Analyze findings
        findings = [
            {
                "id": f"vuln-{i}",
                "title": f"Vulnerability {i}",
                "severity": "critical" if i == 0 else "high",
                "risk_score": 0.9 - (i * 0.1),
            }
            for i in range(2)
        ]

        result = adapter.analyse(
            prompt="Analyze",
            context={"org_id": "integration-test"},
            findings=findings,
        )

        assert result["analyzed"] == 2
        assert result["decision"]
        assert "session_id" in result

        # Get stats
        stats = adapter.get_council_stats()
        assert stats["total_sessions"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=15"])
