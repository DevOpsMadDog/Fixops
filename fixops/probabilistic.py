"""Probabilistic risk forecasting utilities for FixOps."""
from __future__ import annotations

from dataclasses import dataclass
from math import log2
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

_SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _coerce_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    label = str(value).strip().lower()
    if not label:
        return None
    synonym_map = {
        "sev1": "critical",
        "sev2": "high",
        "sev3": "medium",
        "sev4": "low",
        "warning": "medium",
        "error": "high",
        "critical": "critical",
    }
    label = synonym_map.get(label, label)
    if label not in _SEVERITY_ORDER:
        return None
    return label


def _extract_state_sequence(incident: Mapping[str, Any]) -> list[str]:
    states: list[str] = []
    timeline = (
        incident.get("states")
        or incident.get("timeline")
        or incident.get("progression")
        or incident.get("transition_history")
    )
    if isinstance(timeline, Sequence) and not isinstance(timeline, (str, bytes)):
        for entry in timeline:
            if isinstance(entry, Mapping):
                candidate = (
                    entry.get("state")
                    or entry.get("severity")
                    or entry.get("level")
                    or entry.get("name")
                )
            else:
                candidate = entry
            severity = _coerce_severity(candidate)
            if severity:
                states.append(severity)
    if not states:
        start = _coerce_severity(
            incident.get("initial_severity") or incident.get("start_severity")
        )
        end = _coerce_severity(
            incident.get("final_severity")
            or incident.get("resolved_severity")
            or incident.get("severity")
        )
        if start and end:
            states = [start, end]
        elif end:
            states = [end]
    return states


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


@dataclass
class CalibrationResult:
    prior: Dict[str, float]
    transitions: Dict[str, Dict[str, float]]
    incident_count: int
    transition_observations: int
    validation: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bayesian_prior": {key: round(value, 4) for key, value in self.prior.items()},
            "markov_transitions": {
                state: {target: round(weight, 4) for target, weight in row.items()}
                for state, row in self.transitions.items()
            },
            "metrics": {
                "incidents": self.incident_count,
                "transition_observations": self.transition_observations,
                "validation": self.validation,
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

    def validate_transitions(
        self, transitions: Optional[Mapping[str, Mapping[str, Any]]] = None
    ) -> Dict[str, Any]:
        rows: Dict[str, Dict[str, Any]] = {}
        payload = transitions or self.transitions
        all_valid = True
        for state, row in payload.items():
            invalid_targets: list[str] = []
            total = 0.0
            for target, weight in row.items():
                target_key = _coerce_severity(target)
                if target_key is None:
                    invalid_targets.append(str(target))
                    continue
                try:
                    total += float(weight)
                except (TypeError, ValueError):
                    invalid_targets.append(str(target))
            valid_row = not invalid_targets and abs(total - 1.0) <= 1e-3
            rows[str(state)] = {
                "total": round(total, 6),
                "invalid_targets": invalid_targets,
                "valid": valid_row,
            }
            if not valid_row:
                all_valid = False
        return {"valid": all_valid, "rows": rows}

    def _calibrate_transitions(
        self, transition_counts: Mapping[str, Mapping[str, float]]
    ) -> Dict[str, Dict[str, float]]:
        updated: Dict[str, Dict[str, float]] = {}
        baseline = dict(self.transitions)
        for state, baseline_row in baseline.items():
            state_key = _coerce_severity(state)
            if state_key is None:
                continue
            updated[state_key] = dict(baseline_row)
        for state, counts in transition_counts.items():
            state_key = _coerce_severity(state)
            if state_key is None:
                continue
            updated.setdefault(state_key, dict(self._default_transitions().get(state_key, {})))
            for target, value in counts.items():
                target_key = _coerce_severity(target)
                if target_key is None:
                    continue
                updated[state_key][target_key] = updated[state_key].get(target_key, 0.0) + value
        for state in _SEVERITY_ORDER:
            if state not in updated:
                updated[state] = dict(self._default_transitions().get(state, {}))
        calibrated: Dict[str, Dict[str, float]] = {}
        for state, row in updated.items():
            calibrated[state] = _normalise_transition_row(row)
        return calibrated

    def calibrate(
        self,
        incidents: Sequence[Mapping[str, Any]],
        *,
        enforce_validation: bool = False,
    ) -> CalibrationResult:
        severity_counts: Dict[str, float] = {severity: 0.0 for severity in _SEVERITY_ORDER}
        transition_counts: Dict[str, Dict[str, float]] = {}
        incident_count = 0
        transition_observations = 0
        for incident in incidents:
            if not isinstance(incident, Mapping):
                continue
            states = _extract_state_sequence(incident)
            if not states:
                continue
            incident_count += 1
            final_state = states[-1]
            if final_state in severity_counts:
                severity_counts[final_state] += 1.0
            if len(states) >= 2:
                for source, target in zip(states, states[1:]):
                    source_key = _coerce_severity(source)
                    target_key = _coerce_severity(target)
                    if source_key is None or target_key is None:
                        continue
                    transition_counts.setdefault(source_key, {})
                    transition_counts[source_key][target_key] = (
                        transition_counts[source_key].get(target_key, 0.0) + 1.0
                    )
                    transition_observations += 1

        if incident_count == 0:
            raise ValueError("No valid incidents were provided for calibration")

        posterior = self._posterior(severity_counts)
        calibrated_transitions = self._calibrate_transitions(transition_counts)
        validation = self.validate_transitions(calibrated_transitions)
        if enforce_validation and not validation["valid"]:
            raise ValueError("Calibrated transition matrix failed validation checks")

        self.prior = posterior
        self.transitions = calibrated_transitions

        return CalibrationResult(
            prior=posterior,
            transitions=calibrated_transitions,
            incident_count=incident_count,
            transition_observations=transition_observations,
            validation=validation,
        )

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


__all__ = ["ProbabilisticForecastEngine", "CalibrationResult"]
