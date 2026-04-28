from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.enrichment_add_enrichment_data import EnrichmentAddEnrichmentData


T = TypeVar("T", bound="EnrichmentAdd")


@_attrs_define
class EnrichmentAdd:
    """
    Attributes:
        enrichment_source (str):
        enrichment_data (EnrichmentAddEnrichmentData | Unset):
    """

    enrichment_source: str
    enrichment_data: EnrichmentAddEnrichmentData | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enrichment_source = self.enrichment_source

        enrichment_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.enrichment_data, Unset):
            enrichment_data = self.enrichment_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "enrichment_source": enrichment_source,
            }
        )
        if enrichment_data is not UNSET:
            field_dict["enrichment_data"] = enrichment_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.enrichment_add_enrichment_data import EnrichmentAddEnrichmentData

        d = dict(src_dict)
        enrichment_source = d.pop("enrichment_source")

        _enrichment_data = d.pop("enrichment_data", UNSET)
        enrichment_data: EnrichmentAddEnrichmentData | Unset
        if isinstance(_enrichment_data, Unset):
            enrichment_data = UNSET
        else:
            enrichment_data = EnrichmentAddEnrichmentData.from_dict(_enrichment_data)

        enrichment_add = cls(
            enrichment_source=enrichment_source,
            enrichment_data=enrichment_data,
        )

        enrichment_add.additional_properties = d
        return enrichment_add

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
