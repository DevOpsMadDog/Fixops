"""Causal Inference Engine for ALdeci.

This module implements causal inference for vulnerability root cause
analysis and counterfactual reasoning.

Features:
- Directed Acyclic Graph (DAG) construction for security relationships
- Counterfactual "what if" analysis
- Root cause vs symptom differentiation
- Treatment effect estimation for security controls
- SHAP-based explainability
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Set, Tuple


class CausalRelation(Enum):
    """Types of causal relationships in security."""

    ENABLES = "enables"  # A enables B to happen
    CAUSES = "causes"  # A directly causes B
    AMPLIFIES = "amplifies"  # A increases severity of B
    MITIGATES = "mitigates"  # A reduces impact of B
    REQUIRES = "requires"  # B requires A to succeed
    CORRELATES = "correlates"  # A and B are correlated (not causal)


class SecurityFactor(Enum):
    """Security factors in the causal model."""

    # Vulnerability factors
    VULNERABILITY_EXISTS = "vulnerability_exists"
    CODE_REACHABLE = "code_reachable"
    EXPLOIT_AVAILABLE = "exploit_available"

    # Exposure factors
    INTERNET_EXPOSED = "internet_exposed"
    AUTH_REQUIRED = "auth_required"
    NETWORK_SEGMENTED = "network_segmented"

    # Attack factors
    ATTACKER_MOTIVATED = "attacker_motivated"
    ATTACK_ATTEMPTED = "attack_attempted"
    ATTACK_SUCCESSFUL = "attack_successful"

    # Impact factors
    DATA_ACCESSED = "data_accessed"
    SYSTEM_COMPROMISED = "system_compromised"
    LATERAL_MOVEMENT = "lateral_movement"

    # Control factors
    WAF_ENABLED = "waf_enabled"
    IDS_ENABLED = "ids_enabled"
    PATCHED = "patched"
    COMPENSATING_CONTROL = "compensating_control"


@dataclass
class CausalEdge:
    """Edge in the causal graph."""

    source: SecurityFactor
    target: SecurityFactor
    relation: CausalRelation
    strength: float = 1.0  # 0-1, how strong the causal effect
    conditional_on: List[SecurityFactor] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.value,
            "target": self.target.value,
            "relation": self.relation.value,
            "strength": self.strength,
            "conditional_on": [f.value for f in self.conditional_on],
        }


@dataclass
class CounterfactualResult:
    """Result of counterfactual analysis."""

    intervention: str
    original_outcome_prob: float
    counterfactual_outcome_prob: float
    treatment_effect: float
    confidence: float
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intervention": self.intervention,
            "original_outcome_prob": round(self.original_outcome_prob, 4),
            "counterfactual_outcome_prob": round(self.counterfactual_outcome_prob, 4),
            "treatment_effect": round(self.treatment_effect, 4),
            "effect_reduction_percent": round(
                (1 - self.counterfactual_outcome_prob / self.original_outcome_prob)
                * 100,
                1,
            )
            if self.original_outcome_prob > 0
            else 0,
            "confidence": round(self.confidence, 2),
            "explanation": self.explanation,
        }


@dataclass
class RootCauseResult:
    """Result of root cause analysis."""

    symptom: str
    root_causes: List[Tuple[str, float]]  # (cause, contribution)
    causal_chain: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symptom": self.symptom,
            "root_causes": [
                {"factor": cause, "contribution": round(contrib, 4)}
                for cause, contrib in self.root_causes
            ],
            "causal_chain": self.causal_chain,
            "recommendations": self.recommendations,
        }


class CausalSecurityGraph:
    """Directed Acyclic Graph for security causal relationships.

    This graph models how security factors causally influence each other,
    enabling root cause analysis and counterfactual reasoning.
    """

    def __init__(self):
        """Initialize with standard security causal structure."""
        self.edges: List[CausalEdge] = []
        self.factors: Set[SecurityFactor] = set()
        self._build_default_graph()

    def _build_default_graph(self):
        """Build the default causal graph for security analysis."""

        # Vulnerability → Attack chain
        self.add_edge(
            SecurityFactor.VULNERABILITY_EXISTS,
            SecurityFactor.ATTACK_SUCCESSFUL,
            CausalRelation.ENABLES,
            strength=0.9,
        )

        self.add_edge(
            SecurityFactor.CODE_REACHABLE,
            SecurityFactor.ATTACK_SUCCESSFUL,
            CausalRelation.REQUIRES,
            strength=0.95,
        )

        self.add_edge(
            SecurityFactor.EXPLOIT_AVAILABLE,
            SecurityFactor.ATTACK_ATTEMPTED,
            CausalRelation.AMPLIFIES,
            strength=0.8,
        )

        # Exposure → Attack probability
        self.add_edge(
            SecurityFactor.INTERNET_EXPOSED,
            SecurityFactor.ATTACK_ATTEMPTED,
            CausalRelation.AMPLIFIES,
            strength=0.85,
        )

        self.add_edge(
            SecurityFactor.AUTH_REQUIRED,
            SecurityFactor.ATTACK_SUCCESSFUL,
            CausalRelation.MITIGATES,
            strength=0.6,
        )

        self.add_edge(
            SecurityFactor.NETWORK_SEGMENTED,
            SecurityFactor.LATERAL_MOVEMENT,
            CausalRelation.MITIGATES,
            strength=0.7,
        )

        # Attack → Impact
        self.add_edge(
            SecurityFactor.ATTACK_ATTEMPTED,
            SecurityFactor.ATTACK_SUCCESSFUL,
            CausalRelation.ENABLES,
            strength=0.4,  # Base success rate without other factors
        )

        self.add_edge(
            SecurityFactor.ATTACK_SUCCESSFUL,
            SecurityFactor.DATA_ACCESSED,
            CausalRelation.CAUSES,
            strength=0.7,
        )

        self.add_edge(
            SecurityFactor.ATTACK_SUCCESSFUL,
            SecurityFactor.SYSTEM_COMPROMISED,
            CausalRelation.CAUSES,
            strength=0.5,
        )

        self.add_edge(
            SecurityFactor.SYSTEM_COMPROMISED,
            SecurityFactor.LATERAL_MOVEMENT,
            CausalRelation.ENABLES,
            strength=0.6,
        )

        # Controls → Mitigation
        self.add_edge(
            SecurityFactor.WAF_ENABLED,
            SecurityFactor.ATTACK_SUCCESSFUL,
            CausalRelation.MITIGATES,
            strength=0.5,
        )

        self.add_edge(
            SecurityFactor.IDS_ENABLED,
            SecurityFactor.LATERAL_MOVEMENT,
            CausalRelation.MITIGATES,
            strength=0.4,
        )

        self.add_edge(
            SecurityFactor.PATCHED,
            SecurityFactor.VULNERABILITY_EXISTS,
            CausalRelation.MITIGATES,
            strength=0.95,
        )

        self.add_edge(
            SecurityFactor.COMPENSATING_CONTROL,
            SecurityFactor.ATTACK_SUCCESSFUL,
            CausalRelation.MITIGATES,
            strength=0.6,
        )

    def add_edge(
        self,
        source: SecurityFactor,
        target: SecurityFactor,
        relation: CausalRelation,
        strength: float = 1.0,
        conditional_on: List[SecurityFactor] | None = None,
    ):
        """Add a causal edge to the graph."""
        edge = CausalEdge(
            source=source,
            target=target,
            relation=relation,
            strength=strength,
            conditional_on=conditional_on or [],
        )
        self.edges.append(edge)
        self.factors.add(source)
        self.factors.add(target)

    def get_parents(self, factor: SecurityFactor) -> List[CausalEdge]:
        """Get all incoming edges (causes) for a factor."""
        return [e for e in self.edges if e.target == factor]

    def get_children(self, factor: SecurityFactor) -> List[CausalEdge]:
        """Get all outgoing edges (effects) for a factor."""
        return [e for e in self.edges if e.source == factor]

    def get_ancestors(self, factor: SecurityFactor) -> Set[SecurityFactor]:
        """Get all ancestor factors (recursive causes)."""
        ancestors = set()
        queue = [e.source for e in self.get_parents(factor)]

        while queue:
            current = queue.pop(0)
            if current not in ancestors:
                ancestors.add(current)
                queue.extend(e.source for e in self.get_parents(current))

        return ancestors

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary."""
        return {
            "factors": [f.value for f in self.factors],
            "edges": [e.to_dict() for e in self.edges],
        }


class CausalInferenceEngine:
    """Causal inference engine for security analysis.

    Provides:
    - Counterfactual analysis ("What if we had patched?")
    - Root cause identification
    - Treatment effect estimation
    - Causal explanation generation
    """

    def __init__(self, graph: CausalSecurityGraph | None = None):
        """Initialize with causal graph."""
        self.graph = graph or CausalSecurityGraph()

    def compute_outcome_probability(
        self,
        outcome: SecurityFactor,
        evidence: Dict[SecurityFactor, bool],
    ) -> float:
        """Compute probability of outcome given evidence.

        Uses a simplified structural causal model where:
        - ENABLES: P(B|A) = strength
        - CAUSES: P(B|A) = strength
        - AMPLIFIES: P(B) *= (1 + strength) if A
        - MITIGATES: P(B) *= (1 - strength) if A
        - REQUIRES: P(B) = 0 if not A
        """
        # Start with base probability
        base_prob = 0.3  # Prior probability

        # Get all parent edges
        parents = self.graph.get_parents(outcome)

        if not parents:
            return base_prob

        prob = base_prob

        for edge in parents:
            source_value = evidence.get(edge.source)

            if source_value is None:
                continue  # Unknown, use prior

            if edge.relation == CausalRelation.REQUIRES:
                if not source_value:
                    return 0.0  # Required factor is false

            elif edge.relation == CausalRelation.ENABLES:
                if source_value:
                    prob = max(prob, edge.strength)

            elif edge.relation == CausalRelation.CAUSES:
                if source_value:
                    prob = max(prob, edge.strength)

            elif edge.relation == CausalRelation.AMPLIFIES:
                if source_value:
                    prob = min(1.0, prob * (1 + edge.strength))

            elif edge.relation == CausalRelation.MITIGATES:
                if source_value:
                    prob *= 1 - edge.strength

        return min(1.0, max(0.0, prob))

    def counterfactual_analysis(
        self,
        outcome: SecurityFactor,
        current_evidence: Dict[SecurityFactor, bool],
        intervention: SecurityFactor,
        intervention_value: bool,
    ) -> CounterfactualResult:
        """Analyze counterfactual: "What if intervention had been different?"

        Args:
            outcome: The outcome factor we care about
            current_evidence: Current state of the world
            intervention: Factor to intervene on
            intervention_value: New value for the intervention

        Returns:
            CounterfactualResult with treatment effect
        """
        # Calculate original outcome probability
        original_prob = self.compute_outcome_probability(outcome, current_evidence)

        # Create counterfactual world
        cf_evidence = current_evidence.copy()
        cf_evidence[intervention] = intervention_value

        # Calculate counterfactual outcome probability
        cf_prob = self.compute_outcome_probability(outcome, cf_evidence)

        # Treatment effect
        treatment_effect = original_prob - cf_prob

        # Generate explanation
        if intervention_value:
            intervention_desc = f"enabling {intervention.value}"
        else:
            intervention_desc = f"disabling {intervention.value}"

        if treatment_effect > 0.1:
            effect_desc = "significantly reduces"
        elif treatment_effect > 0.01:
            effect_desc = "moderately reduces"
        elif treatment_effect < -0.1:
            effect_desc = "significantly increases"
        elif treatment_effect < -0.01:
            effect_desc = "moderately increases"
        else:
            effect_desc = "has minimal effect on"

        explanation = (
            f"Counterfactual analysis: {intervention_desc} {effect_desc} "
            f"the probability of {outcome.value} from {original_prob:.1%} to {cf_prob:.1%}."
        )

        # Confidence based on graph coverage
        covered_factors = sum(1 for f in current_evidence if f in self.graph.factors)
        confidence = min(0.95, 0.5 + (covered_factors / len(self.graph.factors)) * 0.45)

        return CounterfactualResult(
            intervention=f"{intervention.value}={intervention_value}",
            original_outcome_prob=original_prob,
            counterfactual_outcome_prob=cf_prob,
            treatment_effect=treatment_effect,
            confidence=confidence,
            explanation=explanation,
        )

    def identify_root_causes(
        self,
        symptom: SecurityFactor,
        evidence: Dict[SecurityFactor, bool],
    ) -> RootCauseResult:
        """Identify root causes of a security symptom.

        Uses causal graph traversal to find upstream factors that
        contribute to the observed symptom.
        """
        # Get all ancestors
        ancestors = self.graph.get_ancestors(symptom)

        # Calculate contribution of each ancestor
        contributions = []

        for ancestor in ancestors:
            # Is this ancestor active in the evidence?
            if ancestor not in evidence:
                continue

            if not evidence[ancestor]:
                continue  # Inactive factors don't contribute

            # Calculate causal strength along path
            path_strength = self._calculate_path_strength(ancestor, symptom)

            if path_strength > 0:
                contributions.append((ancestor.value, path_strength))

        # Sort by contribution
        contributions.sort(key=lambda x: x[1], reverse=True)

        # Build causal chain
        causal_chain = self._build_causal_chain(symptom, evidence)

        # Generate recommendations
        recommendations = self._generate_recommendations(contributions, symptom)

        return RootCauseResult(
            symptom=symptom.value,
            root_causes=contributions[:5],  # Top 5 causes
            causal_chain=causal_chain,
            recommendations=recommendations,
        )

    def _calculate_path_strength(
        self,
        source: SecurityFactor,
        target: SecurityFactor,
        visited: Set[SecurityFactor] | None = None,
    ) -> float:
        """Calculate cumulative causal strength from source to target."""
        if visited is None:
            visited = set()

        if source in visited:
            return 0.0

        if source == target:
            return 1.0

        visited.add(source)

        max_strength = 0.0
        for edge in self.graph.get_children(source):
            if edge.relation == CausalRelation.MITIGATES:
                continue  # Skip mitigation edges for root cause

            child_strength = self._calculate_path_strength(edge.target, target, visited)
            if child_strength > 0:
                combined = edge.strength * child_strength
                max_strength = max(max_strength, combined)

        return max_strength

    def _build_causal_chain(
        self,
        symptom: SecurityFactor,
        evidence: Dict[SecurityFactor, bool],
    ) -> List[str]:
        """Build the causal chain leading to the symptom."""
        chain = [symptom.value]
        current = symptom

        for _ in range(10):  # Max depth
            parents = self.graph.get_parents(current)
            active_parents = [
                e
                for e in parents
                if e.source in evidence
                and evidence[e.source]
                and e.relation != CausalRelation.MITIGATES
            ]

            if not active_parents:
                break

            # Pick strongest active parent
            strongest = max(active_parents, key=lambda e: e.strength)
            chain.insert(0, strongest.source.value)
            current = strongest.source

        return chain

    def _generate_recommendations(
        self,
        contributions: List[Tuple[str, float]],
        symptom: SecurityFactor,
    ) -> List[str]:
        """Generate recommendations based on root causes."""
        recommendations = []

        # Map factors to recommendations
        factor_recommendations = {
            "vulnerability_exists": "Apply security patches or update to fixed version",
            "code_reachable": "Refactor code to eliminate reachable attack surface",
            "exploit_available": "Prioritize patching - known exploit in the wild",
            "internet_exposed": "Restrict network access or add WAF protection",
            "attacker_motivated": "High-value target - implement defense in depth",
            "attack_attempted": "Review security logs and enhance monitoring",
        }

        for factor, contribution in contributions[:3]:
            if factor in factor_recommendations:
                recommendations.append(
                    f"[{contribution:.0%} impact] {factor_recommendations[factor]}"
                )

        # Add control recommendations
        control_recommendations = {
            SecurityFactor.ATTACK_SUCCESSFUL: [
                "Enable Web Application Firewall (WAF)",
                "Implement runtime application self-protection (RASP)",
            ],
            SecurityFactor.LATERAL_MOVEMENT: [
                "Implement network segmentation",
                "Deploy micro-segmentation",
                "Enable host-based intrusion detection",
            ],
            SecurityFactor.DATA_ACCESSED: [
                "Encrypt sensitive data at rest and in transit",
                "Implement data loss prevention (DLP)",
            ],
        }

        if symptom in control_recommendations:
            recommendations.extend(control_recommendations[symptom][:2])

        return recommendations

    def explain_risk_factors(
        self,
        evidence: Dict[SecurityFactor, bool],
        outcome: SecurityFactor = SecurityFactor.ATTACK_SUCCESSFUL,
    ) -> Dict[str, Any]:
        """Generate SHAP-like explanations for risk factors.

        For each factor, calculates how much it contributes to or
        reduces the final risk probability.
        """
        base_prob = 0.3  # Base rate
        current_prob = self.compute_outcome_probability(outcome, evidence)

        contributions = {}

        for factor, value in evidence.items():
            if factor == outcome:
                continue

            # Calculate marginal contribution
            without_factor = {k: v for k, v in evidence.items() if k != factor}
            prob_without = self.compute_outcome_probability(outcome, without_factor)

            contribution = current_prob - prob_without
            contributions[factor.value] = {
                "value": value,
                "contribution": round(contribution, 4),
                "effect": "increases"
                if contribution > 0
                else "decreases"
                if contribution < 0
                else "neutral",
            }

        # Sort by absolute contribution
        sorted_contributions = dict(
            sorted(
                contributions.items(),
                key=lambda x: abs(x[1]["contribution"]),
                reverse=True,
            )
        )

        return {
            "outcome": outcome.value,
            "base_probability": base_prob,
            "final_probability": round(current_prob, 4),
            "factor_contributions": sorted_contributions,
            "top_risk_drivers": [
                k for k, v in sorted_contributions.items() if v["contribution"] > 0
            ][:3],
            "top_mitigations": [
                k for k, v in sorted_contributions.items() if v["contribution"] < 0
            ][:3],
        }


# Convenience functions for API use
def analyze_vulnerability_causes(
    has_exploit: bool = False,
    is_reachable: bool = True,
    is_internet_facing: bool = False,
    has_waf: bool = False,
    is_patched: bool = False,
    has_auth: bool = True,
) -> Dict[str, Any]:
    """Analyze root causes and counterfactuals for a vulnerability.

    Returns comprehensive causal analysis including:
    - Current risk factors
    - Root cause chain
    - What-if scenarios for controls
    - Recommendations
    """
    engine = CausalInferenceEngine()

    evidence = {
        SecurityFactor.VULNERABILITY_EXISTS: not is_patched,
        SecurityFactor.CODE_REACHABLE: is_reachable,
        SecurityFactor.EXPLOIT_AVAILABLE: has_exploit,
        SecurityFactor.INTERNET_EXPOSED: is_internet_facing,
        SecurityFactor.WAF_ENABLED: has_waf,
        SecurityFactor.PATCHED: is_patched,
        SecurityFactor.AUTH_REQUIRED: has_auth,
    }

    outcome = SecurityFactor.ATTACK_SUCCESSFUL

    # Current probability
    current_prob = engine.compute_outcome_probability(outcome, evidence)

    # Root cause analysis
    root_causes = engine.identify_root_causes(outcome, evidence)

    # Key counterfactuals
    counterfactuals = []

    if not is_patched:
        cf = engine.counterfactual_analysis(
            outcome,
            evidence,
            SecurityFactor.PATCHED,
            True,
        )
        counterfactuals.append(cf.to_dict())

    if not has_waf and is_internet_facing:
        cf = engine.counterfactual_analysis(
            outcome,
            evidence,
            SecurityFactor.WAF_ENABLED,
            True,
        )
        counterfactuals.append(cf.to_dict())

    if is_internet_facing:
        cf = engine.counterfactual_analysis(
            outcome,
            evidence,
            SecurityFactor.INTERNET_EXPOSED,
            False,
        )
        counterfactuals.append(cf.to_dict())

    # Factor explanations
    explanations = engine.explain_risk_factors(evidence, outcome)

    return {
        "current_risk_probability": round(current_prob, 4),
        "root_cause_analysis": root_causes.to_dict(),
        "counterfactual_scenarios": counterfactuals,
        "factor_explanations": explanations,
        "summary": {
            "risk_level": "critical"
            if current_prob > 0.7
            else "high"
            if current_prob > 0.4
            else "medium"
            if current_prob > 0.2
            else "low",
            "primary_driver": root_causes.root_causes[0][0]
            if root_causes.root_causes
            else "unknown",
            "best_mitigation": counterfactuals[0]["intervention"]
            if counterfactuals
            else "patch the vulnerability",
            "mitigation_effectiveness": f"{counterfactuals[0]['effect_reduction_percent']}%"
            if counterfactuals
            else "unknown",
        },
    }
