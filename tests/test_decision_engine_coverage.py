"""Tests for DecisionEngine — enums, dataclasses, and initialization."""
import pytest

from core.services.enterprise.decision_engine import (
    DecisionOutcome,
    DecisionContext,
    DecisionResult,
    DecisionEngine,
)


class TestDecisionOutcome:
    def test_values(self):
        assert DecisionOutcome.ALLOW.value == "ALLOW"
        assert DecisionOutcome.BLOCK.value == "BLOCK"
        assert DecisionOutcome.DEFER.value == "DEFER"

    def test_count(self):
        assert len(DecisionOutcome) == 3


class TestDecisionContext:
    def test_create_minimal(self):
        ctx = DecisionContext(
            service_name="api-gw",
            environment="production",
            business_context={"team": "platform"},
            security_findings=[],
        )
        assert ctx.service_name == "api-gw"
        assert ctx.environment == "production"
        assert ctx.threat_model is None
        assert ctx.sbom_data is None
        assert ctx.runtime_data is None

    def test_create_full(self):
        ctx = DecisionContext(
            service_name="payment-svc",
            environment="staging",
            business_context={"criticality": "high"},
            security_findings=[
                {"id": "CVE-2024-001", "severity": "CRITICAL"},
                {"id": "CVE-2024-002", "severity": "HIGH"},
            ],
            threat_model={"vectors": ["sqli", "xss"]},
            sbom_data={"components": 42},
            runtime_data={"cpu": 0.8},
        )
        assert len(ctx.security_findings) == 2
        assert ctx.threat_model is not None
        assert ctx.sbom_data is not None


class TestDecisionResult:
    def test_create_minimal(self):
        result = DecisionResult(
            decision=DecisionOutcome.ALLOW,
            confidence_score=0.95,
            consensus_details={"models": 3, "agreement": 0.9},
            evidence_id="ev-001",
            reasoning="Low risk finding",
            validation_results={"passed": True},
            processing_time_us=450.0,
            context_sources=["nvd", "epss"],
        )
        assert result.decision == DecisionOutcome.ALLOW
        assert result.confidence_score == 0.95
        assert result.enterprise_mode is True
        assert result.explainability is None
        assert result.rl_policy is None

    def test_create_full(self):
        result = DecisionResult(
            decision=DecisionOutcome.BLOCK,
            confidence_score=0.99,
            consensus_details={},
            evidence_id="ev-002",
            reasoning="Critical unpatched vulnerability",
            validation_results={},
            processing_time_us=1200.0,
            context_sources=["nvd", "epss", "kev"],
            enterprise_mode=True,
            explainability={"shap_values": [0.3, 0.7]},
            rl_policy={"action": "block", "reward": 1.0},
        )
        assert result.decision == DecisionOutcome.BLOCK
        assert result.explainability is not None
        assert result.rl_policy is not None


class TestDecisionEngine:
    @pytest.fixture
    def engine(self):
        return DecisionEngine()

    def test_init(self, engine):
        assert engine is not None
        assert engine.cache is not None
        assert engine.risk_scorer is not None
        assert engine.explainability_service is not None
        assert engine.rl_controller is not None

    def test_chatgpt_client_initially_none(self, engine):
        # ChatGPT client requires API key to initialize
        assert engine.chatgpt_client is None

    def test_production_components_initially_none(self, engine):
        assert engine.real_vector_db is None
        assert engine.real_jira_client is None
        assert engine.real_confluence_client is None
        assert engine.real_threat_intel is None
        assert engine.oss_integrations is None
        assert engine.processing_layer is None
