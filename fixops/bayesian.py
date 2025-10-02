"""Bayesian prior mapping utilities for vulnerability risk analysis."""
from __future__ import annotations

"""Bayesian prior mapping built on a lightweight pomegranate-compatible API."""

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from pomegranate import BayesianNetwork, State
from pomegranate.distributions import ConditionalProbabilityTable, DiscreteDistribution


DEFAULT_RISK_STATE_WEIGHTS: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.9,
    "medium": 0.5,
    "low": 0.1,
}

DEFAULT_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
    "informational": 0.1,
}


@dataclass
class PosteriorDistribution:
    """Posterior metadata for a single component."""

    distribution: Dict[str, float]
    most_likely: str
    expected_risk: float
    evidence: Dict[str, Any]


class BayesianPriorMapper:
    """Compute component risk posteriors using a Bayesian network."""

    def __init__(
        self,
        risk_node: str = "risk",
        *,
        risk_state_weights: Optional[Mapping[str, float]] = None,
        severity_weights: Optional[Mapping[str, float]] = None,
    ) -> None:
        self.risk_node = risk_node
        self.model: Optional[BayesianNetwork] = None
        self.component_posteriors: Dict[str, PosteriorDistribution] = {}
        self._risk_state_weights = {
            state.lower(): float(weight)
            for state, weight in (risk_state_weights or DEFAULT_RISK_STATE_WEIGHTS).items()
        }
        self._severity_weights = {
            state.lower(): float(weight)
            for state, weight in (severity_weights or DEFAULT_SEVERITY_WEIGHTS).items()
        }

    def update_probabilities(
        self,
        edges: Iterable[Tuple[str, str]],
        cpds: Mapping[str, Any] | Sequence[Tuple[str, Any]],
        component_evidence: Mapping[str, Mapping[str, Any]],
        *,
        query_node: Optional[str] = None,
    ) -> Dict[str, PosteriorDistribution]:
        """Build a Bayesian network and update component posteriors.

        Args:
            edges: Directed edges describing the Bayesian graph structure.
            cpds: Mapping or iterable describing node distributions. Each value may be a
                :class:`pomegranate.distributions.DiscreteDistribution`, a
                :class:`pomegranate.distributions.ConditionalProbabilityTable`, or a
                nested mapping defining the conditional probabilities.
            component_evidence: Mapping from component identifiers to observed evidence
                for the Bayesian nodes.
            query_node: Name of the node whose posterior distribution should be returned.
                Defaults to the ``risk_node`` provided at construction time.

        Returns:
            Mapping from component identifiers to :class:`PosteriorDistribution`.
        """

        normalized_edges = list(edges)
        if not normalized_edges:
            raise ValueError("Bayesian network requires at least one edge")

        distributions = self._normalize_distributions(normalized_edges, cpds)
        model, state_index = self._build_network(normalized_edges, distributions)
        target_node = query_node or self.risk_node
        if target_node not in state_index:
            raise KeyError(f"Unknown query node '{target_node}' in Bayesian network")

        posteriors: Dict[str, PosteriorDistribution] = {}
        for component, evidence in component_evidence.items():
            normalized_evidence = {
                variable: value
                for variable, value in evidence.items()
                if value is not None
            }

            query_result = model.predict_proba(normalized_evidence)
            risk_distribution = query_result[state_index[target_node]]
            if isinstance(risk_distribution, str):
                distribution = {risk_distribution: 1.0}
            else:
                distribution = {
                    state: float(probability)
                    for state, probability in risk_distribution.items()
                }
            expected_risk = self._expected_risk(distribution)
            most_likely = max(distribution, key=distribution.get)

            posteriors[component] = PosteriorDistribution(
                distribution=distribution,
                most_likely=most_likely,
                expected_risk=expected_risk,
                evidence=dict(normalized_evidence),
            )

        self.model = model
        self.component_posteriors = posteriors
        self.risk_node = target_node
        return posteriors

    def _normalize_distributions(
        self,
        edges: Sequence[Tuple[str, str]],
        cpds: Mapping[str, Any] | Sequence[Tuple[str, Any]],
    ) -> Dict[str, Any]:
        """Ensure each node has an associated pomegranate distribution."""

        if isinstance(cpds, Mapping):
            raw = dict(cpds)
        else:
            raw = {name: distribution for name, distribution in cpds}

        parents: Dict[str, list[str]] = defaultdict(list)
        children: Dict[str, list[str]] = defaultdict(list)
        for parent, child in edges:
            parents[child].append(parent)
            children[parent].append(child)

        for node in raw:
            parents.setdefault(node, [])

        distributions: Dict[str, Any] = {}
        processed: set[str] = set()
        queue = deque(node for node, p in parents.items() if not p)

        while queue:
            node = queue.popleft()
            if node in processed:
                continue

            distribution = raw.get(node)
            if distribution is None:
                raise KeyError(f"Missing distribution for node '{node}'")

            parent_nodes = parents[node]
            if isinstance(distribution, (DiscreteDistribution, ConditionalProbabilityTable)):
                distributions[node] = distribution
            elif not parent_nodes:
                distributions[node] = DiscreteDistribution(distribution)
            else:
                if not all(parent in distributions for parent in parent_nodes):
                    queue.append(node)
                    continue
                parent_distributions = [distributions[parent] for parent in parent_nodes]
                table = self._flatten_conditional_table(parent_nodes, distribution)
                distributions[node] = ConditionalProbabilityTable(
                    table, parent_nodes, parent_distributions
                )

            processed.add(node)
            for child in children[node]:
                if child not in processed:
                    queue.append(child)

        if len(distributions) != len(parents):
            missing = set(parents) - set(distributions)
            raise ValueError(
                "Unable to resolve distributions for nodes: " + ", ".join(sorted(missing))
            )

        return distributions

    def _flatten_conditional_table(
        self, parents: Sequence[str], conditional: Mapping[str, Any]
    ) -> Sequence[Sequence[Any]]:
        """Convert nested conditional mappings into CPT rows."""

        table: list[list[Any]] = []

        for parent_state, outcomes in conditional.items():
            if not isinstance(parent_state, tuple):
                parent_state = (parent_state,)
            if len(parent_state) != len(parents):
                raise ValueError("Conditional entry does not match parent arity")

            for state, probability in outcomes.items():
                table.append(list(parent_state) + [state, float(probability)])

        return table

    def _build_network(
        self,
        edges: Sequence[Tuple[str, str]],
        distributions: Mapping[str, Any],
    ) -> Tuple[BayesianNetwork, Dict[str, int]]:
        """Construct a baked BayesianNetwork and index mapping."""

        model = BayesianNetwork("component-risk")
        states = {
            name: State(distribution, name=name)
            for name, distribution in distributions.items()
        }
        model.add_states(*states.values())
        for parent, child in edges:
            model.add_edge(states[parent], states[child])
        model.bake()
        index = {state.name: i for i, state in enumerate(model.states)}
        return model, index

    def _expected_risk(self, distribution: Mapping[str, float]) -> float:
        """Calculate the expected risk from a posterior distribution."""

        weights = self._risk_state_weights
        fallback_scale = 1.0 / max(len(distribution) - 1, 1)

        expected = 0.0
        for index, (state, probability) in enumerate(distribution.items()):
            weight = weights.get(state.lower())
            if weight is None:
                weight = index * fallback_scale
            expected += weight * probability
        return expected

    def _score_vulnerability(self, vulnerability: Mapping[str, Any]) -> float:
        """Compute a scalar risk score for a vulnerability."""

        component = vulnerability.get("component") or vulnerability.get("component_name")
        if not component:
            return 0.0

        posterior = self.component_posteriors.get(component)
        if not posterior:
            return 0.0

        severity = str(vulnerability.get("severity", "medium")).lower()
        severity_weight = self._severity_weights.get(severity, 0.5)
        return posterior.expected_risk * severity_weight

    def attach_component_posterior(self, vulnerability: Mapping[str, Any]) -> Dict[str, Any]:
        """Attach Bayesian posterior metadata to a vulnerability record."""

        enriched: Dict[str, Any] = dict(vulnerability)
        component = enriched.get("component") or enriched.get("component_name")
        if not component:
            return enriched

        posterior = self.component_posteriors.get(component)
        if not posterior:
            return enriched

        enriched["bayesian_posterior"] = dict(posterior.distribution)
        enriched["bayesian_expected_risk"] = posterior.expected_risk
        enriched["bayesian_most_likely_state"] = posterior.most_likely
        enriched["bayesian_score"] = self._score_vulnerability(enriched)
        return enriched
