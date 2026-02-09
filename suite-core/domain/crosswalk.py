"""Domain models for crosswalk correlation results."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Mapping, MutableMapping, Sequence


@dataclass(frozen=True, slots=True)
class CrosswalkRow:
    """Immutable representation of a correlated design component."""

    design_index: int
    design_row: Mapping[str, Any]
    sbom_component: Mapping[str, Any] | None = None
    findings: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    cves: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    business_context: Mapping[str, Any] | None = None
    suppressed: Mapping[str, Sequence[Mapping[str, Any]]] = field(default_factory=dict)

    def with_business_context(self, context: Mapping[str, Any]) -> "CrosswalkRow":
        """Return a copy annotated with business context."""

        return replace(self, business_context=dict(context))

    def with_suppressed(
        self,
        kind: str,
        entries: Sequence[Mapping[str, Any]],
    ) -> "CrosswalkRow":
        """Return a copy with suppressed artefacts recorded."""

        payload: MutableMapping[str, Sequence[Mapping[str, Any]]] = dict(
            self.suppressed
        )
        payload[kind] = tuple(dict(entry) for entry in entries)
        return replace(self, suppressed=dict(payload))

    def with_filtered_findings(
        self,
        findings: Sequence[Mapping[str, Any]],
    ) -> "CrosswalkRow":
        """Return a copy with an updated finding set."""

        return replace(self, findings=tuple(dict(entry) for entry in findings))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "design_index": self.design_index,
            "design_row": dict(self.design_row),
            "sbom_component": (
                dict(self.sbom_component)
                if isinstance(self.sbom_component, Mapping)
                else self.sbom_component
            ),
            "findings": [dict(item) for item in self.findings],
            "cves": [dict(item) for item in self.cves],
        }
        if self.business_context is not None:
            payload["business_context"] = dict(self.business_context)
        if self.suppressed:
            payload["suppressed"] = {
                key: [dict(entry) for entry in value]
                for key, value in self.suppressed.items()
            }
        return payload
