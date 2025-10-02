"""Lightweight subset of the pomegranate distributions API used for testing."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Sequence


@dataclass
class ProbabilityDistribution:
    """Simple container for discrete probability masses."""

    mapping: Dict[str, float]

    def items(self):
        return self.mapping.items()


class DiscreteDistribution:
    """Minimal discrete distribution implementation."""

    def __init__(self, probabilities: Mapping[str, float]):
        total = float(sum(probabilities.values()))
        if total <= 0:
            raise ValueError("DiscreteDistribution requires positive probability mass")
        self.probabilities = {state: float(prob) / total for state, prob in probabilities.items()}

    def items(self):
        return self.probabilities.items()

    def as_probability(self) -> ProbabilityDistribution:
        return ProbabilityDistribution(dict(self.probabilities))


class ConditionalProbabilityTable:
    """Minimal conditional probability table supporting discrete parents."""

    def __init__(
        self,
        table: Sequence[Sequence],
        parent_names: Sequence[str],
        parent_distributions: Sequence[DiscreteDistribution | "ConditionalProbabilityTable"],
    ):
        if len(parent_names) != len(parent_distributions):
            raise ValueError("Parent names and distributions length mismatch")
        self.parent_names = list(parent_names)
        self._table: Dict[tuple, Dict[str, float]] = {}
        for row in table:
            if len(row) != len(parent_names) + 2:
                raise ValueError("Invalid conditional probability table row")
            *parent_states, state, probability = row
            key = tuple(str(value) for value in parent_states)
            self._table.setdefault(key, {})[str(state)] = float(probability)

        # Record all child states for normalization
        states = set()
        for outcomes in self._table.values():
            for state, prob in outcomes.items():
                if prob < 0:
                    raise ValueError("Probabilities must be non-negative")
                states.add(state)
        self.child_states = sorted(states)

    def _normalize(self, probabilities: Dict[str, float]) -> Dict[str, float]:
        total = sum(probabilities.values())
        if total == 0:
            return {state: 0.0 for state in probabilities}
        return {state: value / total for state, value in probabilities.items()}

    def compute(self, parent_probs: Sequence[Mapping[str, float]]) -> Dict[str, float]:
        """Compute the marginal distribution given parent probabilities."""

        result = {state: 0.0 for state in self.child_states}

        def recurse(index: int, weight: float, assignments: List[str]):
            if index == len(self.parent_names):
                probabilities = self._table.get(tuple(assignments))
                if probabilities is None:
                    raise KeyError(
                        f"Missing CPT entry for parent combination {tuple(assignments)}"
                    )
                for state, probability in probabilities.items():
                    result[state] += weight * probability
                return

            for state, probability in parent_probs[index].items():
                recurse(index + 1, weight * probability, assignments + [str(state)])

        recurse(0, 1.0, [])
        return self._normalize(result)

    def items(self):
        raise NotImplementedError("Direct iteration is not supported for CPTs")
