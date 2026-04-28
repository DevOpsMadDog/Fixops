from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichmentRequestCreate")


@_attrs_define
class EnrichmentRequestCreate:
    """
    Attributes:
        indicator (str):
        indicator_type (str):
        sources_queried (int | Unset):  Default: 0.
    """

    indicator: str
    indicator_type: str
    sources_queried: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        indicator = self.indicator

        indicator_type = self.indicator_type

        sources_queried = self.sources_queried

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "indicator": indicator,
                "indicator_type": indicator_type,
            }
        )
        if sources_queried is not UNSET:
            field_dict["sources_queried"] = sources_queried

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        indicator = d.pop("indicator")

        indicator_type = d.pop("indicator_type")

        sources_queried = d.pop("sources_queried", UNSET)

        enrichment_request_create = cls(
            indicator=indicator,
            indicator_type=indicator_type,
            sources_queried=sources_queried,
        )

        enrichment_request_create.additional_properties = d
        return enrichment_request_create

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
