"""Lightweight stand-in for the pomegranate Bayesian network API."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional

from .distributions import ConditionalProbabilityTable, DiscreteDistribution, ProbabilityDistribution


@dataclass
class State:
    distribution: DiscreteDistribution | ConditionalProbabilityTable
    name: str


class BayesianNetwork:
    """Minimal Bayesian network capable of forward inference."""

    def __init__(self, name: str = "network") -> None:
        self.name = name
        self.states: List[State] = []
        self._edges: List[tuple[State, State]] = []
        self._baked = False
        self._state_index: Dict[str, int] = {}
        self._topology: List[str] = []

    def add_states(self, *states: State) -> None:
        self.states.extend(states)
        self._baked = False

    def add_edge(self, parent: State, child: State) -> None:
        self._edges.append((parent, child))
        self._baked = False

    def bake(self) -> None:
        name_to_state = {state.name: state for state in self.states}
        in_degree: Dict[str, int] = {state.name: 0 for state in self.states}
        adjacency: Dict[str, List[str]] = defaultdict(list)

        for parent, child in self._edges:
            if parent.name not in name_to_state or child.name not in name_to_state:
                raise KeyError("Edges must reference added states")
            adjacency[parent.name].append(child.name)
            in_degree[child.name] += 1

        queue = deque(sorted(name for name, degree in in_degree.items() if degree == 0))
        order: List[str] = []
        while queue:
            node = queue.popleft()
            order.append(node)
            for successor in adjacency[node]:
                in_degree[successor] -= 1
                if in_degree[successor] == 0:
                    queue.append(successor)

        if len(order) != len(self.states):
            raise ValueError("BayesianNetwork contains cycles or disconnected states")

        self._state_index = {state.name: index for index, state in enumerate(self.states)}
        self._topology = order
        self._baked = True

    def predict_proba(self, evidence: Optional[Mapping[str, str]] = None):
        if not self._baked:
            self.bake()

        evidence = {str(name): str(value) for name, value in (evidence or {}).items()}
        results: Dict[str, ProbabilityDistribution | str] = {}

        for node in self._topology:
            state = self.states[self._state_index[node]]
            if node in evidence:
                results[node] = evidence[node]
                continue

            distribution = state.distribution
            if isinstance(distribution, DiscreteDistribution):
                results[node] = distribution.as_probability()
            else:
                parent_probs: List[Mapping[str, float]] = []
                for parent_name in distribution.parent_names:
                    parent_result = results.get(parent_name)
                    if parent_result is None:
                        raise KeyError(f"Missing parent distribution for '{parent_name}'")
                    if isinstance(parent_result, str):
                        parent_probs.append({parent_result: 1.0})
                    else:
                        parent_probs.append(parent_result.mapping)
                results[node] = ProbabilityDistribution(distribution.compute(parent_probs))

        return [results[state.name] for state in self.states]


__all__ = [
    "BayesianNetwork",
    "State",
    "DiscreteDistribution",
    "ConditionalProbabilityTable",
    "ProbabilityDistribution",
]
