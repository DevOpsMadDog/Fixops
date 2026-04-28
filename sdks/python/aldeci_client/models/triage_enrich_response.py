from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.triage_enrich_response_enrichment_available import TriageEnrichResponseEnrichmentAvailable
    from ..models.triage_enriched_finding import TriageEnrichedFinding


T = TypeVar("T", bound="TriageEnrichResponse")


@_attrs_define
class TriageEnrichResponse:
    """Response for /enrich.

    Attributes:
        enriched (list[TriageEnrichedFinding]):
        total (int):
        enrichment_available (TriageEnrichResponseEnrichmentAvailable):
        timestamp (str):
    """

    enriched: list[TriageEnrichedFinding]
    total: int
    enrichment_available: TriageEnrichResponseEnrichmentAvailable
    timestamp: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enriched = []
        for enriched_item_data in self.enriched:
            enriched_item = enriched_item_data.to_dict()
            enriched.append(enriched_item)

        total = self.total

        enrichment_available = self.enrichment_available.to_dict()

        timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "enriched": enriched,
                "total": total,
                "enrichment_available": enrichment_available,
                "timestamp": timestamp,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.triage_enrich_response_enrichment_available import TriageEnrichResponseEnrichmentAvailable
        from ..models.triage_enriched_finding import TriageEnrichedFinding

        d = dict(src_dict)
        enriched = []
        _enriched = d.pop("enriched")
        for enriched_item_data in _enriched:
            enriched_item = TriageEnrichedFinding.from_dict(enriched_item_data)

            enriched.append(enriched_item)

        total = d.pop("total")

        enrichment_available = TriageEnrichResponseEnrichmentAvailable.from_dict(d.pop("enrichment_available"))

        timestamp = d.pop("timestamp")

        triage_enrich_response = cls(
            enriched=enriched,
            total=total,
            enrichment_available=enrichment_available,
            timestamp=timestamp,
        )

        triage_enrich_response.additional_properties = d
        return triage_enrich_response

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
