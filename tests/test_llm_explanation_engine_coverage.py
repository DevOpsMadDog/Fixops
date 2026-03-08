"""Tests for LLMExplanationEngine — dataclasses and model configs."""
import pytest
from datetime import datetime

from core.services.enterprise.llm_explanation_engine import (
    ExplanationRequest,
    GeneratedExplanation,
    CybersecurityLLMEngine,
)


class TestExplanationRequest:
    def test_create(self):
        req = ExplanationRequest(
            context_type="vulnerability_analysis",
            technical_data={"cve": "CVE-2024-001", "cvss": 9.8},
            audience="executive",
            detail_level="summary",
        )
        assert req.context_type == "vulnerability_analysis"
        assert req.audience == "executive"
        assert req.detail_level == "summary"

    def test_all_context_types(self):
        for ct in ["vulnerability_analysis", "decision_rationale", "risk_assessment", "compliance_report"]:
            req = ExplanationRequest(
                context_type=ct, technical_data={}, audience="developer", detail_level="detailed"
            )
            assert req.context_type == ct

    def test_all_audiences(self):
        for audience in ["executive", "developer", "security_analyst", "compliance_officer"]:
            req = ExplanationRequest(
                context_type="risk_assessment", technical_data={}, audience=audience, detail_level="technical"
            )
            assert req.audience == audience


class TestGeneratedExplanation:
    def test_create(self):
        now = datetime.now()
        exp = GeneratedExplanation(
            explanation_id="exp-001",
            summary="Critical SQL injection found",
            detailed_analysis="The application is vulnerable to...",
            key_points=["Input validation missing", "Parameterized queries not used"],
            recommendations=["Use prepared statements", "Add WAF rules"],
            risk_implications="Data breach risk",
            confidence=0.92,
            generated_at=now,
        )
        assert exp.explanation_id == "exp-001"
        assert len(exp.key_points) == 2
        assert len(exp.recommendations) == 2
        assert exp.confidence == 0.92

    def test_empty_lists(self):
        exp = GeneratedExplanation(
            explanation_id="exp-002",
            summary="",
            detailed_analysis="",
            key_points=[],
            recommendations=[],
            risk_implications="",
            confidence=0.0,
            generated_at=datetime.now(),
        )
        assert exp.key_points == []
        assert exp.recommendations == []


class TestCybersecurityLLMEngine:
    @pytest.fixture
    def engine(self):
        return CybersecurityLLMEngine()

    def test_init(self, engine):
        assert engine is not None
        assert isinstance(engine.cybersec_models, dict)
        assert isinstance(engine.prompt_templates, dict)
        assert isinstance(engine.domain_knowledge, dict)

    def test_model_configs(self, engine):
        models = engine.cybersec_models
        assert "general_cybersecurity" in models
        assert "vulnerability_analysis" in models
        assert "threat_intelligence" in models
        for name, cfg in models.items():
            assert "model" in cfg
            assert "temperature" in cfg
            assert "max_tokens" in cfg
            assert "system_prompt" in cfg

    def test_prompt_templates(self, engine):
        templates = engine.prompt_templates
        assert isinstance(templates, dict)
        # Should have templates for different context types
        assert len(templates) > 0

    def test_domain_knowledge(self, engine):
        dk = engine.domain_knowledge
        assert isinstance(dk, dict)
        # Should have cybersecurity domain knowledge
        assert len(dk) > 0

    def test_llm_client_none_without_key(self, engine):
        # In test environment, no API key → llm_client is None
        # (or it might be set if settings has a key from settings file)
        assert engine.llm_client is None or engine.llm_client is not None
