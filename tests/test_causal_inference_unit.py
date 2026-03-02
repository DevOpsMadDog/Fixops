"""Unit tests for causal_inference.py — V3 Decision Intelligence.

Tests the CausalSecurityGraph, CausalInferenceEngine, and helper functions
that power ALdeci's root cause analysis and counterfactual reasoning.
"""

from core.causal_inference import (
    CausalEdge,
    CausalInferenceEngine,
    CausalRelation,
    CausalSecurityGraph,
    CounterfactualResult,
    RootCauseResult,
    SecurityFactor,
    analyze_vulnerability_causes,
)


# ---------------------------------------------------------------------------
# CausalRelation / SecurityFactor enums
# ---------------------------------------------------------------------------

class TestEnums:
    def test_causal_relation_values(self):
        assert CausalRelation.ENABLES.value == "enables"
        assert CausalRelation.CAUSES.value == "causes"
        assert CausalRelation.AMPLIFIES.value == "amplifies"
        assert CausalRelation.MITIGATES.value == "mitigates"
        assert CausalRelation.REQUIRES.value == "requires"
        assert CausalRelation.CORRELATES.value == "correlates"

    def test_security_factor_vulnerability_factors(self):
        assert SecurityFactor.VULNERABILITY_EXISTS.value == "vulnerability_exists"
        assert SecurityFactor.CODE_REACHABLE.value == "code_reachable"
        assert SecurityFactor.EXPLOIT_AVAILABLE.value == "exploit_available"

    def test_security_factor_exposure_factors(self):
        assert SecurityFactor.INTERNET_EXPOSED.value == "internet_exposed"
        assert SecurityFactor.AUTH_REQUIRED.value == "auth_required"
        assert SecurityFactor.NETWORK_SEGMENTED.value == "network_segmented"

    def test_security_factor_attack_factors(self):
        assert SecurityFactor.ATTACKER_MOTIVATED.value == "attacker_motivated"
        assert SecurityFactor.ATTACK_ATTEMPTED.value == "attack_attempted"
        assert SecurityFactor.ATTACK_SUCCESSFUL.value == "attack_successful"

    def test_security_factor_control_factors(self):
        assert SecurityFactor.WAF_ENABLED.value == "waf_enabled"
        assert SecurityFactor.IDS_ENABLED.value == "ids_enabled"
        assert SecurityFactor.PATCHED.value == "patched"
        assert SecurityFactor.COMPENSATING_CONTROL.value == "compensating_control"


# ---------------------------------------------------------------------------
# CausalEdge dataclass
# ---------------------------------------------------------------------------

class TestCausalEdge:
    def test_create_edge(self):
        edge = CausalEdge(
            source=SecurityFactor.VULNERABILITY_EXISTS,
            target=SecurityFactor.ATTACK_SUCCESSFUL,
            relation=CausalRelation.ENABLES,
            strength=0.8,
        )
        assert edge.source == SecurityFactor.VULNERABILITY_EXISTS
        assert edge.target == SecurityFactor.ATTACK_SUCCESSFUL
        assert edge.relation == CausalRelation.ENABLES
        assert edge.strength == 0.8

    def test_edge_to_dict(self):
        edge = CausalEdge(
            source=SecurityFactor.VULNERABILITY_EXISTS,
            target=SecurityFactor.ATTACK_SUCCESSFUL,
            relation=CausalRelation.CAUSES,
            strength=0.9,
        )
        d = edge.to_dict()
        assert isinstance(d, dict)
        assert "source" in d
        assert "target" in d
        assert "relation" in d
        assert "strength" in d


# ---------------------------------------------------------------------------
# CounterfactualResult dataclass
# ---------------------------------------------------------------------------

class TestCounterfactualResult:
    def test_create_result(self):
        result = CounterfactualResult(
            intervention="patching",
            original_outcome_prob=0.8,
            counterfactual_outcome_prob=0.3,
            treatment_effect=0.5,
            confidence=0.85,
            explanation="Patching reduces attack success probability",
        )
        assert result.original_outcome_prob == 0.8
        assert result.counterfactual_outcome_prob == 0.3
        assert result.treatment_effect == 0.5

    def test_result_to_dict(self):
        result = CounterfactualResult(
            intervention="waf_enabled",
            original_outcome_prob=0.8,
            counterfactual_outcome_prob=0.3,
            treatment_effect=0.5,
            confidence=0.7,
            explanation="WAF blocks attack",
        )
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "original_outcome_prob" in d
        assert "counterfactual_outcome_prob" in d


# ---------------------------------------------------------------------------
# RootCauseResult dataclass
# ---------------------------------------------------------------------------

class TestRootCauseResult:
    def test_create_root_cause(self):
        result = RootCauseResult(
            symptom="attack_successful",
            root_causes=[("vulnerability_exists", 0.9)],
            causal_chain=["vulnerability_exists", "attack_attempted", "attack_successful"],
            recommendations=["Apply patch immediately"],
        )
        assert result.symptom == "attack_successful"
        assert len(result.root_causes) == 1

    def test_root_cause_to_dict(self):
        result = RootCauseResult(
            symptom="data_accessed",
            root_causes=[("internet_exposed", 0.8)],
            causal_chain=["internet_exposed", "attack_attempted"],
            recommendations=["Enable WAF"],
        )
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "root_causes" in d


# ---------------------------------------------------------------------------
# CausalSecurityGraph
# ---------------------------------------------------------------------------

class TestCausalSecurityGraph:
    def test_default_graph_construction(self):
        graph = CausalSecurityGraph()
        d = graph.to_dict()
        assert isinstance(d, dict)

    def test_add_edge(self):
        graph = CausalSecurityGraph()
        graph.add_edge(
            source=SecurityFactor.WAF_ENABLED,
            target=SecurityFactor.ATTACK_SUCCESSFUL,
            relation=CausalRelation.MITIGATES,
            strength=0.7,
        )
        children = graph.get_children(SecurityFactor.WAF_ENABLED)
        target_factors = [e.target for e in children]
        assert SecurityFactor.ATTACK_SUCCESSFUL in target_factors

    def test_get_parents(self):
        graph = CausalSecurityGraph()
        parents = graph.get_parents(SecurityFactor.ATTACK_SUCCESSFUL)
        assert isinstance(parents, list)

    def test_get_children(self):
        graph = CausalSecurityGraph()
        children = graph.get_children(SecurityFactor.VULNERABILITY_EXISTS)
        assert isinstance(children, list)

    def test_get_ancestors(self):
        graph = CausalSecurityGraph()
        ancestors = graph.get_ancestors(SecurityFactor.ATTACK_SUCCESSFUL)
        assert isinstance(ancestors, set)

    def test_to_dict(self):
        graph = CausalSecurityGraph()
        d = graph.to_dict()
        assert isinstance(d, dict)


# ---------------------------------------------------------------------------
# CausalInferenceEngine
# ---------------------------------------------------------------------------

class TestCausalInferenceEngine:
    def setup_method(self):
        self.graph = CausalSecurityGraph()
        self.engine = CausalInferenceEngine(graph=self.graph)

    def test_init_default_graph(self):
        engine = CausalInferenceEngine()
        assert engine is not None

    def test_init_custom_graph(self):
        engine = CausalInferenceEngine(graph=self.graph)
        assert engine is not None

    def test_compute_outcome_probability(self):
        evidence = {
            SecurityFactor.VULNERABILITY_EXISTS: True,
            SecurityFactor.INTERNET_EXPOSED: True,
            SecurityFactor.EXPLOIT_AVAILABLE: True,
        }
        prob = self.engine.compute_outcome_probability(
            outcome=SecurityFactor.ATTACK_SUCCESSFUL,
            evidence=evidence,
        )
        assert isinstance(prob, float)
        assert 0.0 <= prob <= 1.0

    def test_compute_outcome_low_probability(self):
        evidence = {
            SecurityFactor.VULNERABILITY_EXISTS: False,
            SecurityFactor.PATCHED: True,
        }
        prob = self.engine.compute_outcome_probability(
            outcome=SecurityFactor.ATTACK_SUCCESSFUL,
            evidence=evidence,
        )
        assert isinstance(prob, float)
        assert 0.0 <= prob <= 1.0

    def test_counterfactual_analysis(self):
        current_evidence = {
            SecurityFactor.VULNERABILITY_EXISTS: True,
            SecurityFactor.INTERNET_EXPOSED: True,
            SecurityFactor.EXPLOIT_AVAILABLE: True,
        }
        result = self.engine.counterfactual_analysis(
            outcome=SecurityFactor.ATTACK_SUCCESSFUL,
            current_evidence=current_evidence,
            intervention=SecurityFactor.PATCHED,
            intervention_value=True,
        )
        assert isinstance(result, CounterfactualResult)
        assert isinstance(result.original_outcome_prob, float)
        assert isinstance(result.counterfactual_outcome_prob, float)

    def test_counterfactual_with_waf(self):
        current_evidence = {
            SecurityFactor.VULNERABILITY_EXISTS: True,
            SecurityFactor.INTERNET_EXPOSED: True,
        }
        result = self.engine.counterfactual_analysis(
            outcome=SecurityFactor.ATTACK_SUCCESSFUL,
            current_evidence=current_evidence,
            intervention=SecurityFactor.WAF_ENABLED,
            intervention_value=True,
        )
        assert isinstance(result, CounterfactualResult)

    def test_identify_root_causes(self):
        evidence = {
            SecurityFactor.VULNERABILITY_EXISTS: True,
            SecurityFactor.INTERNET_EXPOSED: True,
            SecurityFactor.EXPLOIT_AVAILABLE: True,
            SecurityFactor.ATTACK_SUCCESSFUL: True,
        }
        result = self.engine.identify_root_causes(
            symptom=SecurityFactor.ATTACK_SUCCESSFUL,
            evidence=evidence,
        )
        assert isinstance(result, RootCauseResult)
        assert isinstance(result.root_causes, list)

    def test_explain_risk_factors(self):
        evidence = {
            SecurityFactor.VULNERABILITY_EXISTS: True,
            SecurityFactor.INTERNET_EXPOSED: True,
        }
        explanation = self.engine.explain_risk_factors(
            evidence=evidence,
            outcome=SecurityFactor.ATTACK_SUCCESSFUL,
        )
        assert isinstance(explanation, dict)

    def test_explain_risk_with_controls(self):
        evidence = {
            SecurityFactor.VULNERABILITY_EXISTS: True,
            SecurityFactor.WAF_ENABLED: True,
            SecurityFactor.IDS_ENABLED: True,
        }
        explanation = self.engine.explain_risk_factors(
            evidence=evidence,
            outcome=SecurityFactor.ATTACK_SUCCESSFUL,
        )
        assert isinstance(explanation, dict)


# ---------------------------------------------------------------------------
# Module-level function
# ---------------------------------------------------------------------------

class TestAnalyzeVulnerabilityCauses:
    def test_basic_analysis(self):
        result = analyze_vulnerability_causes(
            has_exploit=True,
            is_reachable=True,
            is_internet_facing=True,
            has_auth=False,
        )
        assert isinstance(result, dict)

    def test_analysis_with_controls(self):
        result = analyze_vulnerability_causes(
            has_exploit=True,
            is_internet_facing=True,
            has_auth=True,
            has_waf=True,
        )
        assert isinstance(result, dict)

    def test_analysis_no_exploit(self):
        result = analyze_vulnerability_causes(
            has_exploit=False,
            is_reachable=True,
            is_internet_facing=True,
        )
        assert isinstance(result, dict)

    def test_analysis_patched(self):
        result = analyze_vulnerability_causes(
            has_exploit=True,
            is_internet_facing=True,
            is_patched=True,
        )
        assert isinstance(result, dict)

    def test_analysis_defaults(self):
        result = analyze_vulnerability_causes()
        assert isinstance(result, dict)
