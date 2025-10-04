"""Lightweight SSVC stub tailored for the FixOps test-suite."""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any


@dataclass
class DecisionOutcome:
    """Represents the result of evaluating an SSVC decision."""

    action: Any
    priority: Any
    vector: str
    timestamp: str


class Decision:
    """Facade that dispatches to methodology specific implementations."""

    def __init__(self, methodology: str, **kwargs: Any) -> None:
        self.methodology = methodology.lower()
        module_name = f"ssvc.plugins.{self.methodology}"
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown SSVC methodology '{methodology}'") from exc

        decision_cls = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and attr_name.lower().startswith("decision"):
                decision_cls = attr
                break

        if decision_cls is None:  # pragma: no cover - ensure clear failure in tests
            raise ValueError(f"Methodology '{methodology}' does not expose a Decision class")

        self._decision_instance = decision_cls(**kwargs)
        self._last_outcome: DecisionOutcome | None = None

    def evaluate(self) -> DecisionOutcome:
        outcome = self._decision_instance.evaluate()
        if not isinstance(outcome, DecisionOutcome):
            raise TypeError("Decision implementations must return a DecisionOutcome instance")
        self._last_outcome = outcome
        return outcome

    def to_vector(self) -> str:
        if hasattr(self._decision_instance, "to_vector"):
            return self._decision_instance.to_vector()
        raise NotImplementedError("Decision implementation does not support vector serialisation")


__all__ = ["Decision", "DecisionOutcome"]
