"""Unit tests for enhanced_decision.py — V3 Decision Intelligence.

Tests the MultiLLMConsensusEngine and EnhancedDecisionEngine that powers
ALdeci's multi-LLM voting and decision intelligence.
"""

from core.enhanced_decision import (
    EnhancedDecisionEngine,
    ModelAnalysis,
    MultiLLMConsensusEngine,
    MultiLLMResult,
    ProviderSpec,
    _as_counter,
    _attack_vectors,
    _build_summary,
    _determine_highest,
    _extract_compliance_gaps,
    _extract_exploit_stats,
    _extract_exposures,
    _majority,
    _mitre_for_focus,
    _normalise_severity,
    _promote,
)


# ---------------------------------------------------------------------------
# ProviderSpec dataclass — (name, weight=1.0, style='consensus', focus=[])
# ---------------------------------------------------------------------------

class TestProviderSpec:
    def test_create_spec(self):
        spec = ProviderSpec(name="openai", weight=1.0)
        assert spec.name == "openai"
        assert spec.weight == 1.0

    def test_default_values(self):
        spec = ProviderSpec(name="anthropic")
        assert spec.weight == 1.0
        assert spec.style == "consensus"
        assert isinstance(spec.focus, list)


# ---------------------------------------------------------------------------
# ModelAnalysis — (provider, recommended_action, confidence, reasoning, ...)
# ---------------------------------------------------------------------------

class TestModelAnalysis:
    def test_create_analysis(self):
        analysis = ModelAnalysis(
            provider="openai",
            recommended_action="immediate_patch",
            confidence=0.92,
            reasoning="High CVSS and active exploitation",
        )
        assert analysis.provider == "openai"
        assert analysis.confidence == 0.92

    def test_to_dict(self):
        analysis = ModelAnalysis(
            provider="anthropic",
            recommended_action="patch_within_24h",
            confidence=0.85,
            reasoning="EPSS > 0.5",
        )
        d = analysis.to_dict()
        assert isinstance(d, dict)
        assert d["provider"] == "anthropic"

    def test_defaults(self):
        analysis = ModelAnalysis(
            provider="gemini",
            recommended_action="monitor",
            confidence=0.5,
            reasoning="Low severity",
        )
        assert analysis.processing_time_ms == 0
        assert analysis.cost_usd == 0.0
        assert analysis.risk_assessment == "moderate"


# ---------------------------------------------------------------------------
# MultiLLMResult — (final_decision, consensus_confidence, method, individual_analyses, ...)
# ---------------------------------------------------------------------------

class TestMultiLLMResult:
    def test_create_result(self):
        analyses = [
            ModelAnalysis(
                provider=f"provider-{i}",
                recommended_action="patch",
                confidence=0.8 + i * 0.05,
                reasoning=f"Reason {i}",
            )
            for i in range(3)
        ]
        result = MultiLLMResult(
            final_decision="immediate_patch",
            consensus_confidence=0.85,
            method="weighted_majority",
            individual_analyses=analyses,
        )
        assert result.final_decision == "immediate_patch"
        assert result.consensus_confidence == 0.85

    def test_to_dict(self):
        result = MultiLLMResult(
            final_decision="defer",
            consensus_confidence=0.95,
            method="unanimous",
            individual_analyses=[],
        )
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "final_decision" in d


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    def test_normalise_severity_string(self):
        assert _normalise_severity("CRITICAL") == "critical"
        assert _normalise_severity("HIGH") == "high"
        assert _normalise_severity("Medium") == "medium"
        assert _normalise_severity("low") == "low"

    def test_normalise_severity_numeric(self):
        result = _normalise_severity(9.5)
        assert result in ("critical", "high", "medium", "low")

    def test_normalise_severity_none(self):
        result = _normalise_severity(None)
        assert result in ("low", "medium", "unknown")

    def test_as_counter_dict(self):
        result = _as_counter({"critical": 5, "high": 3})
        assert isinstance(result, dict)
        assert result.get("critical", 0) == 5

    def test_as_counter_none(self):
        result = _as_counter(None)
        assert isinstance(result, dict)

    def test_determine_highest(self):
        counts = {"critical": 2, "high": 5, "medium": 3}
        result = _determine_highest(counts)
        assert result in ("critical", "high", "medium", "low")

    def test_determine_highest_empty(self):
        result = _determine_highest({})
        assert isinstance(result, str)

    def test_promote_action(self):
        result = _promote("monitor")
        assert isinstance(result, str)

    def test_mitre_for_focus(self):
        focus = ["sql_injection", "xss"]
        result = _mitre_for_focus(focus)
        assert isinstance(result, list)

    def test_mitre_for_focus_empty(self):
        result = _mitre_for_focus([])
        assert isinstance(result, list)

    def test_attack_vectors(self):
        result = _attack_vectors(
            exposures=[{"type": "internet", "count": 3}],
            exploit_stats={"exploited_count": 5},
        )
        assert isinstance(result, list)

    def test_extract_exposures(self):
        summary = {"exposures": [{"type": "internet", "count": 3}]}
        result = _extract_exposures(summary)
        assert isinstance(result, list)

    def test_extract_exposures_none(self):
        result = _extract_exposures(None)
        assert isinstance(result, list)

    def test_extract_compliance_gaps(self):
        status = {"gaps": ["SOC2-CC6.1", "PCI-DSS-6.5.1"]}
        result = _extract_compliance_gaps(status)
        assert isinstance(result, list)

    def test_extract_compliance_gaps_none(self):
        result = _extract_compliance_gaps(None)
        assert isinstance(result, list)

    def test_extract_exploit_stats(self):
        summary = {"exploit_stats": {"kev_count": 3, "epss_max": 0.85}}
        result = _extract_exploit_stats(summary)
        assert isinstance(result, dict)

    def test_extract_exploit_stats_none(self):
        result = _extract_exploit_stats(None)
        assert isinstance(result, dict)

    def test_build_summary(self):
        result = _build_summary(
            decision="immediate_patch",
            confidence=0.9,
            counts={"critical": 2, "high": 3},
            exposures=[{"type": "internet"}],
            exploit_stats={"exploited_count": 1},
        )
        assert isinstance(result, str)

    def test_majority_unanimous(self):
        votes = ["patch", "patch", "patch"]
        result = _majority(votes, fallback="monitor")
        assert result == "patch"

    def test_majority_split(self):
        votes = ["patch", "patch", "monitor"]
        result = _majority(votes, fallback="defer")
        assert result in ("patch", "monitor")

    def test_majority_empty(self):
        result = _majority([], fallback="defer")
        assert result == "defer"


# ---------------------------------------------------------------------------
# MultiLLMConsensusEngine
# ---------------------------------------------------------------------------

class TestMultiLLMConsensusEngine:
    def test_init_default(self):
        engine = MultiLLMConsensusEngine()
        assert engine is not None

    def test_init_with_settings(self):
        settings = {"threshold": 0.85}
        engine = MultiLLMConsensusEngine(settings=settings)
        assert engine is not None

    def test_provider_names_property(self):
        engine = MultiLLMConsensusEngine()
        names = engine.provider_names
        assert isinstance(names, list)

    def test_knowledge_graph_summary_property(self):
        engine = MultiLLMConsensusEngine()
        summary = engine.knowledge_graph_summary
        assert isinstance(summary, dict)

    def test_ssvc_label(self):
        label = MultiLLMConsensusEngine.ssvc_label("immediate", 0.95)
        assert isinstance(label, str)

    def test_ssvc_label_low_confidence(self):
        label = MultiLLMConsensusEngine.ssvc_label("defer", 0.3)
        assert isinstance(label, str)

    def test_evaluate_from_payload(self):
        engine = MultiLLMConsensusEngine()
        payload = {
            "findings": [
                {"severity": "high", "title": "SQLi in login", "cvss": 8.5}
            ],
            "severity_counts": {"critical": 1, "high": 5, "medium": 10},
        }
        result = engine.evaluate_from_payload(payload)
        assert isinstance(result, MultiLLMResult)
        assert isinstance(result.final_decision, str)


# ---------------------------------------------------------------------------
# EnhancedDecisionEngine
# ---------------------------------------------------------------------------

class TestEnhancedDecisionEngine:
    def test_init(self):
        engine = EnhancedDecisionEngine()
        assert engine is not None

    def test_capabilities(self):
        engine = EnhancedDecisionEngine()
        caps = engine.capabilities()
        assert isinstance(caps, dict)

    def test_analyse_payload(self):
        engine = EnhancedDecisionEngine()
        payload = {
            "findings": [
                {"severity": "critical", "title": "RCE", "cvss": 9.8}
            ],
            "severity_counts": {"critical": 1},
        }
        result = engine.analyse_payload(payload)
        assert isinstance(result, dict)

    def test_signals(self):
        engine = EnhancedDecisionEngine()
        signals = engine.signals(verdict="immediate_patch", confidence=0.9)
        assert isinstance(signals, dict)

    def test_signals_defaults(self):
        engine = EnhancedDecisionEngine()
        signals = engine.signals()
        assert isinstance(signals, dict)
