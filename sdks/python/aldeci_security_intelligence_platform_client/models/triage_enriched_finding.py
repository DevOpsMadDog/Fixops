from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.attack_path_summary import AttackPathSummary
    from ..models.compliance_impact import ComplianceImpact
    from ..models.triage_enriched_finding_finding import TriageEnrichedFindingFinding


T = TypeVar("T", bound="TriageEnrichedFinding")


@_attrs_define
class TriageEnrichedFinding:
    """Enriched finding returned from /enrich.

    Attributes:
        finding (TriageEnrichedFindingFinding):
        attack_paths (AttackPathSummary): Summarized attack path information for a finding.
        compliance_impact (ComplianceImpact): Compliance framework impact for a finding.
        sla_deadline (str):
        sla_hours_remaining (float):
        recommended_action (str):
        confidence_adjustment (float | None | Unset):
        enrichment_sources (list[str] | Unset):
    """

    finding: TriageEnrichedFindingFinding
    attack_paths: AttackPathSummary
    compliance_impact: ComplianceImpact
    sla_deadline: str
    sla_hours_remaining: float
    recommended_action: str
    confidence_adjustment: float | None | Unset = UNSET
    enrichment_sources: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding.to_dict()

        attack_paths = self.attack_paths.to_dict()

        compliance_impact = self.compliance_impact.to_dict()

        sla_deadline = self.sla_deadline

        sla_hours_remaining = self.sla_hours_remaining

        recommended_action = self.recommended_action

        confidence_adjustment: float | None | Unset
        if isinstance(self.confidence_adjustment, Unset):
            confidence_adjustment = UNSET
        else:
            confidence_adjustment = self.confidence_adjustment

        enrichment_sources: list[str] | Unset = UNSET
        if not isinstance(self.enrichment_sources, Unset):
            enrichment_sources = self.enrichment_sources

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
                "attack_paths": attack_paths,
                "compliance_impact": compliance_impact,
                "sla_deadline": sla_deadline,
                "sla_hours_remaining": sla_hours_remaining,
                "recommended_action": recommended_action,
            }
        )
        if confidence_adjustment is not UNSET:
            field_dict["confidence_adjustment"] = confidence_adjustment
        if enrichment_sources is not UNSET:
            field_dict["enrichment_sources"] = enrichment_sources

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.attack_path_summary import AttackPathSummary
        from ..models.compliance_impact import ComplianceImpact
        from ..models.triage_enriched_finding_finding import TriageEnrichedFindingFinding

        d = dict(src_dict)
        finding = TriageEnrichedFindingFinding.from_dict(d.pop("finding"))

        attack_paths = AttackPathSummary.from_dict(d.pop("attack_paths"))

        compliance_impact = ComplianceImpact.from_dict(d.pop("compliance_impact"))

        sla_deadline = d.pop("sla_deadline")

        sla_hours_remaining = d.pop("sla_hours_remaining")

        recommended_action = d.pop("recommended_action")

        def _parse_confidence_adjustment(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        confidence_adjustment = _parse_confidence_adjustment(d.pop("confidence_adjustment", UNSET))

        enrichment_sources = cast(list[str], d.pop("enrichment_sources", UNSET))

        triage_enriched_finding = cls(
            finding=finding,
            attack_paths=attack_paths,
            compliance_impact=compliance_impact,
            sla_deadline=sla_deadline,
            sla_hours_remaining=sla_hours_remaining,
            recommended_action=recommended_action,
            confidence_adjustment=confidence_adjustment,
            enrichment_sources=enrichment_sources,
        )

        triage_enriched_finding.additional_properties = d
        return triage_enriched_finding

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
