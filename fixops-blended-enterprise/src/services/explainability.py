"""Deterministic explainability helpers for DecisionFactory alignment."""

from __future__ import annotations

from statistics import mean
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence

import structlog

logger = structlog.get_logger()


def _normalise_feature_name(name: str) -> str:
    return name.replace(" ", "_").lower()


class ExplainabilityService:
    """Generate SHAP/LIME-style feature attributions without heavy dependencies."""

    def __init__(self) -> None:
        self._baseline: Dict[str, float] = {}

    def prime_baseline(self, training_examples: Iterable[Mapping[str, float]]) -> None:
        """Seed baselines from historical feature vectors."""

        aggregates: Dict[str, List[float]] = {}
        for example in training_examples or []:
            if not isinstance(example, Mapping):
                continue
            for key, value in example.items():
                try:
                    numeric = float(value)
                except (TypeError, ValueError):
                    continue
                aggregates.setdefault(_normalise_feature_name(str(key)), []).append(numeric)

        self._baseline = {feature: mean(values) for feature, values in aggregates.items() if values}
        logger.debug("Explainability baseline primed", features=len(self._baseline))

    def explain(self, feature_vector: Mapping[str, float]) -> Dict[str, float]:
        """Return signed contributions for an individual feature vector."""

        contributions: Dict[str, float] = {}
        for key, value in feature_vector.items():
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                continue

            feature = _normalise_feature_name(str(key))
            baseline = self._baseline.get(feature, 0.0)
            contributions[feature] = round(numeric - baseline, 4)

        return contributions

    def generate_narrative(
        self,
        feature_vector: Mapping[str, float],
        contributions: Mapping[str, float],
    ) -> str:
        """Generate a deterministic natural-language summary."""

        influential = sorted(contributions.items(), key=lambda item: abs(item[1]), reverse=True)[:3]
        if not influential:
            return "Feature values match the tenant baseline; no dominant drivers detected."

        fragments = []
        for feature, delta in influential:
            direction = "increased" if delta > 0 else "decreased"
            fragments.append(f"{feature.replace('_', ' ')} {direction} risk by {abs(delta):.2f}")

        return ", ".join(fragments)

    def enrich_findings(
        self,
        findings: Iterable[Mapping[str, object]],
        feature_keys: Sequence[str] | None = None,
    ) -> Sequence[MutableMapping[str, object]]:
        """Attach explainability artefacts to findings."""

        annotated = []
        for finding in findings or []:
            if not isinstance(finding, Mapping):
                continue
            feature_vector: Dict[str, float] = {}
            for key in feature_keys or []:
                try:
                    feature_vector[key] = float(finding.get(key, 0))
                except (TypeError, ValueError):
                    continue

            contributions = self.explain(feature_vector)
            narrative = self.generate_narrative(feature_vector, contributions)

            clone = dict(finding)
            clone.setdefault("explainability", {})
            if isinstance(clone["explainability"], MutableMapping):
                payload = dict(clone["explainability"])
            else:
                payload = {}

            payload.update({
                "contributions": contributions,
                "narrative": narrative,
            })
            clone["explainability"] = payload
            annotated.append(clone)

        return annotated


__all__ = ["ExplainabilityService"]
