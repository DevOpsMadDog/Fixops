"""Context Engine for deriving FixOps business-aware signals."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

_SEVERITY_ORDER = ("low", "medium", "high", "critical")
_SARIF_LEVEL_MAP = {
    None: "low",
    "": "low",
    "none": "low",
    "note": "low",
    "info": "low",
    "warning": "medium",
    "error": "high",
}
_CVE_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
}


@dataclass
class ComponentContext:
    """Computed context for a design/SBOM component."""

    name: str
    severity: str
    context_score: int
    criticality: str
    data_classification: List[str]
    exposure: str
    signals: Dict[str, Any]
    playbook: Dict[str, Any]


class ContextEngine:
    """Business-aware context derivation using overlay configuration."""

    def __init__(self, settings: Mapping[str, Any]):
        self.settings = dict(settings or {})
        fields = self.settings.get("fields", {}) if isinstance(settings, Mapping) else {}
        self.criticality_field = str(fields.get("criticality", "customer_impact"))
        self.data_field = str(fields.get("data", "data_classification"))
        self.exposure_field = str(fields.get("exposure", "exposure"))
        self.criticality_weights = self._normalise_weights(
            self.settings.get("criticality_weights"), default={"mission_critical": 4, "internal": 1}
        )
        self.data_weights = self._normalise_weights(
            self.settings.get("data_weights"), default={"pii": 4, "internal": 2, "public": 1}
        )
        self.exposure_weights = self._normalise_weights(
            self.settings.get("exposure_weights"), default={"internet": 3, "internal": 1}
        )
        self.playbooks = self._parse_playbooks(self.settings.get("playbooks", []))

    @staticmethod
    def _normalise_weights(raw: Any, *, default: Mapping[str, int]) -> Dict[str, int]:
        weights: Dict[str, int] = {k.lower(): int(v) for k, v in default.items()}
        if isinstance(raw, Mapping):
            for key, value in raw.items():
                try:
                    weights[str(key).lower()] = int(value)
                except (TypeError, ValueError):
                    continue
        return weights

    @staticmethod
    def _parse_playbooks(raw: Any) -> List[Dict[str, Any]]:
        playbooks: List[Dict[str, Any]] = []
        if isinstance(raw, Iterable):
            for item in raw:
                if not isinstance(item, Mapping):
                    continue
                entry = {k: v for k, v in item.items() if k is not None}
                if "min_score" in entry:
                    try:
                        entry["min_score"] = int(entry["min_score"])
                    except (TypeError, ValueError):
                        entry["min_score"] = 0
                else:
                    entry["min_score"] = 0
                playbooks.append(entry)
        playbooks.sort(key=lambda item: item.get("min_score", 0), reverse=True)
        return playbooks

    @staticmethod
    def _severity_index(severity: str) -> int:
        try:
            return _SEVERITY_ORDER.index(severity)
        except ValueError:
            return _SEVERITY_ORDER.index("medium")

    def _normalise_sarif_severity(self, level: Optional[str]) -> str:
        if level is None:
            return "low"
        normalised = _SARIF_LEVEL_MAP.get(level.lower()) if isinstance(level, str) else None
        if normalised:
            return normalised
        return "medium"

    def _normalise_cve_severity(self, severity: Optional[str]) -> str:
        if not severity:
            return "medium"
        return _CVE_SEVERITY_MAP.get(str(severity).lower(), "medium")

    def _evaluate_playbook(self, score: int) -> Dict[str, Any]:
        for playbook in self.playbooks:
            if score >= playbook.get("min_score", 0):
                return dict(playbook)
        return {"name": "Monitor", "min_score": 0}

    def _score_value(self, value: Optional[str], weights: Mapping[str, int]) -> int:
        if not value:
            return 0
        return weights.get(str(value).lower(), 0)

    def _score_data_classification(self, classification: Any) -> int:
        if isinstance(classification, (list, tuple, set)):
            return max((self._score_value(item, self.data_weights) for item in classification), default=0)
        return self._score_value(classification, self.data_weights)

    def _extract_component_name(self, entry: Mapping[str, Any]) -> str:
        for key in ("component", "Component", "service", "name"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return "unknown"

    def _derive_component_context(
        self, entry: Mapping[str, Any], crosswalk_item: Mapping[str, Any]
    ) -> ComponentContext:
        findings = crosswalk_item.get("findings", []) if isinstance(crosswalk_item, Mapping) else []
        cves = crosswalk_item.get("cves", []) if isinstance(crosswalk_item, Mapping) else []
        highest = "low"
        exploited = False
        for finding in findings:
            level = finding.get("level") if isinstance(finding, Mapping) else None
            severity = self._normalise_sarif_severity(level if isinstance(level, str) else None)
            if self._severity_index(severity) > self._severity_index(highest):
                highest = severity
        for record in cves:
            severity = self._normalise_cve_severity(record.get("severity") if isinstance(record, Mapping) else None)
            if self._severity_index(severity) > self._severity_index(highest):
                highest = severity
            exploited = exploited or bool(record.get("exploited"))
        criticality = str(entry.get(self.criticality_field, "unknown")).lower()
        data_raw = entry.get(self.data_field)
        exposure = str(entry.get(self.exposure_field, "internal"))
        score = (
            self._score_value(criticality, self.criticality_weights)
            + self._score_data_classification(data_raw)
            + self._score_value(exposure, self.exposure_weights)
            + self._severity_index(highest)
        )
        if exploited:
            score += 1
        playbook = self._evaluate_playbook(score)
        signals = {
            "exploited": exploited,
            "finding_count": len(findings),
            "cve_count": len(cves),
        }
        classification = data_raw if isinstance(data_raw, list) else [data_raw] if data_raw else []
        return ComponentContext(
            name=self._extract_component_name(entry),
            severity=highest,
            context_score=score,
            criticality=criticality or "unknown",
            data_classification=[str(item) for item in classification if item],
            exposure=str(exposure).lower(),
            signals=signals,
            playbook=playbook,
        )

    def evaluate(
        self,
        design_rows: Sequence[Mapping[str, Any]],
        crosswalk: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        components: List[ComponentContext] = []
        crosswalk_by_component = {
            self._extract_component_name(item.get("design_row", {})): item for item in crosswalk
            if isinstance(item, Mapping)
        }
        for row in design_rows:
            if not isinstance(row, Mapping):
                continue
            name = self._extract_component_name(row)
            crosswalk_entry = crosswalk_by_component.get(name, {"findings": [], "cves": []})
            component_context = self._derive_component_context(row, crosswalk_entry)
            components.append(component_context)

        if not components:
            return {"summary": {"components_evaluated": 0}, "components": []}

        highest_score = max(component.context_score for component in components)
        average_score = sum(component.context_score for component in components) / len(components)
        highest_component = max(components, key=lambda item: item.context_score)

        summary = {
            "components_evaluated": len(components),
            "highest_score": highest_score,
            "average_score": round(average_score, 2),
            "highest_component": {
                "name": highest_component.name,
                "score": highest_component.context_score,
                "playbook": highest_component.playbook,
            },
        }
        signals = {
            "criticality_distribution": self._bucket(components, key=lambda item: item.criticality),
            "exposure_distribution": self._bucket(components, key=lambda item: item.exposure),
            "playbook_usage": self._bucket(components, key=lambda item: item.playbook.get("name", "unknown")),
        }
        summary["signals"] = signals

        component_payloads = [
            {
                "name": component.name,
                "severity": component.severity,
                "context_score": component.context_score,
                "criticality": component.criticality,
                "data_classification": component.data_classification,
                "exposure": component.exposure,
                "signals": component.signals,
                "playbook": component.playbook,
            }
            for component in components
        ]
        return {"summary": summary, "components": component_payloads}

    @staticmethod
    def _bucket(components: Iterable[ComponentContext], key) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for component in components:
            bucket = key(component) if callable(key) else "unknown"
            bucket_key = str(bucket or "unknown")
            counts[bucket_key] = counts.get(bucket_key, 0) + 1
        return counts


__all__ = ["ContextEngine", "ComponentContext"]
