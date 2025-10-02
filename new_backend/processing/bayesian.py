"""Bayesian inference utilities for component risk modelling."""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

_BACKEND: Optional[str] = None

try:  # pragma: no cover - import guard
    from pgmpy.factors.discrete import TabularCPD
    from pgmpy.inference import VariableElimination
    from pgmpy.models import BayesianNetwork

    _BACKEND = "pgmpy"
    import numpy as _np  # type: ignore
    if not hasattr(_np, 'product'):
        _np.product = _np.prod  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - fallback to pomegranate
    try:
        from pomegranate import BayesianNetwork as PomegranateNetwork
        from pomegranate.distributions import DiscreteDistribution
        from pomegranate import ConditionalProbabilityTable, Node

        _BACKEND = "pomegranate"
    except ImportError as exc:  # pragma: no cover - handled in tests
        raise RuntimeError(
            "Either pgmpy or pomegranate must be installed to use the Bayesian processing module."
        ) from exc


@dataclass(frozen=True)
class ComponentNode:
    """Configuration for a single component node in the Bayesian network."""

    name: str
    states: Sequence[str]
    cpt: Sequence[Sequence[float]]
    parents: Sequence[str] = field(default_factory=tuple)
    parent_states: Mapping[str, Sequence[str]] = field(default_factory=dict)

    def to_cpd(self) -> TabularCPD:
        """Create a :class:`TabularCPD` for the component (pgmpy backend)."""

        if _BACKEND != "pgmpy":  # pragma: no cover - only executed when pgmpy installed
            raise RuntimeError("TabularCPD conversion is only valid for the pgmpy backend.")

        state_names: Dict[str, Sequence[str]] = {self.name: list(self.states)}
        evidence: List[str] = list(self.parents)
        evidence_card: List[int] = []

        if evidence:
            if not self.parent_states:
                raise ValueError(
                    f"Parent states must be provided for node '{self.name}' when parents are declared."
                )
            for parent in evidence:
                if parent not in self.parent_states:
                    raise ValueError(
                        f"Missing state definitions for parent '{parent}' of node '{self.name}'."
                    )
                parent_state_names = list(self.parent_states[parent])
                state_names[parent] = parent_state_names
                evidence_card.append(len(parent_state_names))

        return TabularCPD(
            variable=self.name,
            variable_card=len(self.states),
            values=[list(row) for row in self.cpt],
            evidence=evidence or None,
            evidence_card=evidence_card or None,
            state_names=state_names,
        )

    def to_pomegranate(self, parent_nodes: List[Node]) -> Node:
        """Create a pomegranate :class:`Node` for the component."""

        if _BACKEND != "pomegranate":  # pragma: no cover - executed when backend is pgmpy
            raise RuntimeError("Pomegranate conversion is only valid for the pomegranate backend.")

        if parent_nodes:
            parent_state_lists = [self.parent_states[parent.name] for parent in parent_nodes]
            table: List[List[object]] = []
            for column_index, combination in enumerate(product(*parent_state_lists)):
                for state_index, state_name in enumerate(self.states):
                    table.append([
                        *combination,
                        state_name,
                        float(self.cpt[state_index][column_index]),
                    ])

            distributions = [parent.distribution for parent in parent_nodes]
            cpt = ConditionalProbabilityTable(table, distributions)
            node = Node(cpt, name=self.name)
        else:
            probabilities = {state: float(self.cpt[state_index][0]) for state_index, state in enumerate(self.states)}
            distribution = DiscreteDistribution(probabilities)
            node = Node(distribution, name=self.name)

        return node


class BayesianComponentNetwork:
    """Bayesian network that models component health relationships."""

    def __init__(self, components: Sequence[ComponentNode]):
        if not components:
            raise ValueError("At least one component node is required to build a network.")

        self._components = {node.name: node for node in components}

        if _BACKEND == "pgmpy":
            edges = [
                (parent, node.name)
                for node in components
                for parent in node.parents
            ]
            self._model = BayesianNetwork(edges)

            cpds = [node.to_cpd() for node in components]
            self._model.add_cpds(*cpds)
            self._model.check_model()
            self._inference = VariableElimination(self._model)
        elif _BACKEND == "pomegranate":
            self._model = self._build_pomegranate_network(components)
            self._inference = None
        else:  # pragma: no cover - safeguarded by import logic
            raise RuntimeError("No supported Bayesian backend is available.")

    def _build_pomegranate_network(self, components: Sequence[ComponentNode]) -> PomegranateNetwork:
        """Construct a pomegranate Bayesian network respecting parent order."""

        network = PomegranateNetwork("component-network")
        states: Dict[str, Node] = {}
        remaining = {node.name: node for node in components}

        while remaining:
            progress = False
            for name, node in list(remaining.items()):
                if all(parent in states for parent in node.parents):
                    parent_nodes = [states[parent] for parent in node.parents]
                    pomegranate_node = node.to_pomegranate(parent_nodes)
                    network.add_state(pomegranate_node)
                    for parent_node in parent_nodes:
                        network.add_edge(parent_node, pomegranate_node)
                    states[name] = pomegranate_node
                    remaining.pop(name)
                    progress = True
            if not progress:
                missing_parents = {
                    name: [parent for parent in node.parents if parent not in states]
                    for name, node in remaining.items()
                }
                raise ValueError(f"Unresolved parent references in network: {missing_parents}")

        network.bake()
        self._pomegranate_states = states
        return network

    @property
    def model(self):  # pragma: no cover - return type depends on backend
        """Expose the underlying Bayesian model."""

        return self._model

    def update_probabilities(
        self,
        evidence: Optional[Mapping[str, str]] = None,
        targets: Optional[Iterable[str]] = None,
    ) -> Dict[str, Dict[str, float]]:
        """Return posterior probabilities for the requested components."""

        query_nodes = list(targets) if targets else list(self._components.keys())
        evidence = dict(evidence or {})

        if _BACKEND == "pgmpy":
            posteriors: Dict[str, Dict[str, float]] = {}
            for node in query_nodes:
                if node in evidence:
                    observed_state = evidence[node]
                    posteriors[node] = {
                        state: 1.0 if state == observed_state else 0.0
                        for state in self._components[node].states
                    }
                    continue
                result = self._inference.query([node], evidence=evidence, show_progress=False)
                posteriors[node] = {
                    state: float(prob)
                    for state, prob in zip(result.state_names[node], result.values)
                }
            return posteriors

        # pomegranate backend
        beliefs = self._model.predict_proba(evidence)  # type: ignore[union-attr]
        posteriors: Dict[str, Dict[str, float]] = {}
        state_lookup = {state.name: belief for state, belief in zip(self._model.states, beliefs)}  # type: ignore[attr-defined]

        for node in query_nodes:
            belief = state_lookup[node]
            if hasattr(belief, "parameters"):
                distribution = belief.parameters[0]
                posteriors[node] = {state: float(prob) for state, prob in distribution.items()}
            else:
                observed_state = str(belief)
                posteriors[node] = {state: 1.0 if state == observed_state else 0.0 for state in self._components[node].states}

        return posteriors


def update_probabilities(
    network: BayesianComponentNetwork,
    evidence: Optional[Mapping[str, str]] = None,
    targets: Optional[Iterable[str]] = None,
) -> Dict[str, Dict[str, float]]:
    """Convenience wrapper for :meth:`BayesianComponentNetwork.update_probabilities`."""

    return network.update_probabilities(evidence=evidence, targets=targets)


def attach_component_posterior(
    components: Sequence[Mapping[str, object]],
    posteriors: Mapping[str, Mapping[str, float]],
    *,
    posterior_key: str = "posterior",
) -> List[MutableMapping[str, object]]:
    """Attach posterior probabilities to component dictionaries."""

    enriched_components: List[MutableMapping[str, object]] = []

    for component in components:
        component_copy: MutableMapping[str, object] = dict(component)
        name = component_copy.get("name")
        if isinstance(name, str) and name in posteriors:
            component_copy[posterior_key] = dict(posteriors[name])
        enriched_components.append(component_copy)

    return enriched_components


__all__ = [
    "ComponentNode",
    "BayesianComponentNetwork",
    "update_probabilities",
    "attach_component_posterior",
]
