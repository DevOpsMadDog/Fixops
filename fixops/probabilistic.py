"""Probabilistic risk forecasting utilities for FixOps."""
from __future__ import annotations

from dataclasses import dataclass
from math import log2
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

_SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _severity_index(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return _SEVERITY_ORDER.index("medium")


def _normalise_transition_row(row: Mapping[str, Any]) -> Dict[str, float]:
    weights: Dict[str, float] = {}
    total = 0.0
    for key, value in row.items():
        try:
            weight = float(value)
        except (TypeError, ValueError):
            continue
        if weight <= 0:
            continue
        weights[str(key).lower()] = weight
        total += weight
    if not weights or total <= 0:
        return {"low": 1.0}
    return {severity: weight / total for severity, weight in weights.items()}


def _normalise_prior(raw: Mapping[str, Any]) -> Dict[str, float]:
    prior: Dict[str, float] = {severity: 0.5 for severity in _SEVERITY_ORDER}
    total = 0.0
    for severity, value in raw.items():
        key = str(severity).lower()
        if key not in prior:
            continue
        try:
            weight = float(value)
        except (TypeError, ValueError):
            continue
        if weight <= 0:
            continue
        prior[key] = weight
    for value in prior.values():
        total += value
    if total <= 0:
        return {severity: 0.25 for severity in _SEVERITY_ORDER}
    return {severity: weight / total for severity, weight in prior.items()}


def _entropy(distribution: Mapping[str, float]) -> float:
    entropy_value = 0.0
    for probability in distribution.values():
        if probability <= 0:
            continue
        entropy_value -= probability * log2(probability)
    return entropy_value


def _highest_severity(entry: Mapping[str, Any]) -> str:
    highest = "low"
    findings = entry.get("findings")
    if isinstance(findings, Iterable):
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            level = str(finding.get("level") or finding.get("severity") or "").lower()
            if not level:
                continue
            candidate = (
                "critical"
                if level == "critical"
                else "high"
                if level in {"error", "high"}
                else "medium"
                if level in {"warning", "medium"}
                else "low"
            )
            if _severity_index(candidate) > _severity_index(highest):
                highest = candidate
    cves = entry.get("cves")
    if isinstance(cves, Iterable):
        for record in cves:
            if not isinstance(record, Mapping):
                continue
            severity = str(record.get("severity") or "").lower()
            candidate = (
                "critical"
                if severity == "critical"
                else "high"
                if severity in {"high"}
                else "medium"
                if severity in {"medium", "moderate"}
                else "low"
            )
            if _severity_index(candidate) > _severity_index(highest):
                highest = candidate
    return highest


@dataclass
class ComponentForecast:
    name: str
    current_severity: str
    escalation_probability: float
    next_state_distribution: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "current_severity": self.current_severity,
            "escalation_probability": round(self.escalation_probability, 4),
            "next_state_distribution": {
                key: round(value, 4) for key, value in self.next_state_distribution.items()
            },
        }


class ProbabilisticForecastEngine:
    """Combine Bayesian priors and Markov transitions for severity forecasting."""

    def __init__(self, settings: Optional[Mapping[str, Any]] = None):
        payload = dict(settings or {})
        prior_raw = payload.get("bayesian_prior")
        if isinstance(prior_raw, Mapping):
            self.prior = _normalise_prior(prior_raw)
        else:
            self.prior = {severity: 0.25 for severity in _SEVERITY_ORDER}

        transitions_raw = payload.get("markov_transitions")
        if isinstance(transitions_raw, Mapping):
            transitions: Dict[str, Dict[str, float]] = {}
            for state, row in transitions_raw.items():
                if isinstance(row, Mapping):
                    transitions[str(state).lower()] = _normalise_transition_row(row)
            self.transitions = transitions or self._default_transitions()
        else:
            self.transitions = self._default_transitions()

        self.component_limit = int(payload.get("component_limit", 5))
        self.escalation_threshold = _severity_index(payload.get("escalate_from", "medium"))

    @staticmethod
    def _default_transitions() -> Dict[str, Dict[str, float]]:
        return {
            "low": {"low": 0.8, "medium": 0.2},
            "medium": {"medium": 0.6, "high": 0.3, "low": 0.1},
            "high": {"high": 0.6, "critical": 0.25, "medium": 0.15},
            "critical": {"critical": 0.7, "high": 0.3},
        }

    def _posterior(self, counts: Mapping[str, Any]) -> Dict[str, float]:
        totals: Dict[str, float] = {severity: self.prior.get(severity, 0.25) for severity in _SEVERITY_ORDER}
        for severity, value in counts.items():
            key = str(severity).lower()
            if key not in totals:
                continue
            try:
                observed = float(value)
            except (TypeError, ValueError):
                continue
            totals[key] += max(observed, 0.0)
        normaliser = sum(totals.values())
        if normaliser <= 0:
            return {severity: 0.25 for severity in _SEVERITY_ORDER}
        return {severity: value / normaliser for severity, value in totals.items()}

    def _forecast_next_state(self, posterior: Mapping[str, float]) -> Dict[str, float]:
        next_state: Dict[str, float] = {severity: 0.0 for severity in _SEVERITY_ORDER}
        for state, probability in posterior.items():
            row = self.transitions.get(state, self.transitions.get("medium", {"medium": 1.0}))
            for target, weight in row.items():
                key = target if target in next_state else str(target).lower()
                if key not in next_state:
                    next_state[key] = 0.0
                next_state[key] += probability * weight
        normaliser = sum(next_state.values())
        if normaliser <= 0:
            return {severity: 0.25 for severity in _SEVERITY_ORDER}
        return {severity: value / normaliser for severity, value in next_state.items()}

    def _component_forecasts(
        self,
        crosswalk: Sequence[Mapping[str, Any]],
    ) -> list[ComponentForecast]:
        forecasts: list[ComponentForecast] = []
        for entry in crosswalk:
            if not isinstance(entry, Mapping):
                continue
            design_row = entry.get("design_row") if isinstance(entry.get("design_row"), Mapping) else {}
            name = str(design_row.get("component") or design_row.get("Component") or design_row.get("service") or design_row.get("name") or "unknown")
            highest = _highest_severity(entry)
            row = self.transitions.get(highest, self.transitions.get("medium", {"medium": 1.0}))
            escalation_probability = sum(
                weight
                for target, weight in row.items()
                if _severity_index(target) > _severity_index(highest)
            )
            forecasts.append(
                ComponentForecast(
                    name=name,
                    current_severity=highest,
                    escalation_probability=escalation_probability,
                    next_state_distribution=dict(row),
                )
            )
        forecasts.sort(key=lambda item: item.escalation_probability, reverse=True)
        return forecasts[: self.component_limit]

    def evaluate(
        self,
        severity_counts: Mapping[str, Any],
        crosswalk: Sequence[Mapping[str, Any]],
        exploited_records: Iterable[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        posterior = self._posterior(severity_counts)
        next_state = self._forecast_next_state(posterior)
        entropy_bits = _entropy(posterior)
        high_index = _severity_index("high")
        critical_index = _severity_index("critical")
        expected_high = sum(
            probability for severity, probability in posterior.items() if _severity_index(severity) >= high_index
        )
        expected_critical = sum(
            probability for severity, probability in next_state.items() if _severity_index(severity) >= critical_index
        )
        exploited = 0
        for record in exploited_records:
            if not isinstance(record, Mapping):
                continue
            if record.get("exploited") or record.get("knownExploited"):
                exploited += 1
        forecasts = self._component_forecasts(crosswalk)
        escalation_hotspots = [forecast for forecast in forecasts if _severity_index(forecast.current_severity) >= self.escalation_threshold and forecast.escalation_probability >= 0.2]
        notes: list[str] = []
        if exploited:
            notes.append(f"{exploited} exploited vulnerabilities increase prior weight on escalation events")
        if escalation_hotspots:
            component_names = ", ".join(forecast.name for forecast in escalation_hotspots)
            notes.append(
                f"Components likely to escalate: {component_names}"
            )
        if entropy_bits < 1.0:
            notes.append("Posterior distribution is peaked; guardrails may tighten remediation SLAs")

        return {
            "posterior": {key: round(value, 4) for key, value in posterior.items()},
            "next_state": {key: round(value, 4) for key, value in next_state.items()},
            "metrics": {
                "expected_high_or_critical": round(expected_high, 4),
                "expected_critical_next_cycle": round(expected_critical, 4),
                "entropy_bits": round(entropy_bits, 4),
                "exploited_records": exploited,
            },
            "components": [forecast.to_dict() for forecast in forecasts],
            "notes": notes,
        }


__all__ = ["ProbabilisticForecastEngine"]
