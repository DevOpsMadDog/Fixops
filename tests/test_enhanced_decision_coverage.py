"""Coverage tests for core.enhanced_decision — EnhancedDecisionEngine."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.enhanced_decision import EnhancedDecisionEngine, MultiLLMConsensusEngine, ModelAnalysis


class TestModelAnalysis:
    def test_creation(self):
        ma = ModelAnalysis(
            provider="openai",
            recommended_action="patch",
            confidence=0.9,
            reasoning="Test reasoning",
        )
        assert ma.provider == "openai"
        assert ma.confidence == 0.9
        assert ma.recommended_action == "patch"

    def test_defaults(self):
        ma = ModelAnalysis(
            provider="anthropic",
            recommended_action="monitor",
            confidence=0.5,
            reasoning="Low risk",
        )
        assert ma.processing_time_ms == 0
        assert ma.cost_usd == 0.0
        assert ma.risk_assessment == "moderate"
        assert isinstance(ma.mitre_techniques, list)


class TestMultiLLMConsensusEngine:
    def test_instantiation(self):
        engine = MultiLLMConsensusEngine()
        assert engine is not None

    def test_with_settings(self):
        engine = MultiLLMConsensusEngine(settings={"timeout": 30})
        assert engine is not None


class TestEnhancedDecisionEngine:
    def test_instantiation(self):
        engine = EnhancedDecisionEngine()
        assert engine is not None

    def test_with_settings(self):
        engine = EnhancedDecisionEngine(settings={"cache_ttl": 300})
        assert engine is not None

    def test_capabilities(self):
        engine = EnhancedDecisionEngine()
        caps = engine.capabilities()
        assert isinstance(caps, dict)

    def test_evaluate_pipeline(self):
        engine = EnhancedDecisionEngine()
        pipeline_result = {
            "status": "completed",
            "findings": [{"id": "CVE-2024-001", "severity": "high"}],
            "summary": {"total": 1, "critical": 0, "high": 1},
        }
        result = engine.evaluate_pipeline(pipeline_result)
        assert result is not None
        assert isinstance(result, dict)

    def test_evaluate_pipeline_with_context(self):
        engine = EnhancedDecisionEngine()
        result = engine.evaluate_pipeline(
            pipeline_result={"status": "done", "findings": []},
            context_summary={"app_id": "APP-001", "env": "production"},
            compliance_status={"soc2": "compliant"},
        )
        assert isinstance(result, dict)

    def test_analyse_payload(self):
        engine = EnhancedDecisionEngine()
        payload = {
            "finding": {
                "id": "CVE-2024-002",
                "severity": "critical",
                "title": "RCE via deserialization",
                "cvss": 9.8,
            }
        }
        result = engine.analyse_payload(payload)
        assert result is not None
        assert isinstance(result, dict)

    def test_signals(self):
        engine = EnhancedDecisionEngine()
        result = engine.signals()
        assert isinstance(result, dict)

    def test_signals_with_filters(self):
        engine = EnhancedDecisionEngine()
        result = engine.signals(verdict="critical", confidence=0.9)
        assert isinstance(result, dict)
