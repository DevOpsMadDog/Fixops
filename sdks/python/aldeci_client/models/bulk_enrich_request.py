from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.bulk_indicator import BulkIndicator


T = TypeVar("T", bound="BulkEnrichRequest")


@_attrs_define
class BulkEnrichRequest:
    """
    Attributes:
        indicators (list[BulkIndicator]):
    """

    indicators: list[BulkIndicator]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        indicators = []
        for indicators_item_data in self.indicators:
            indicators_item = indicators_item_data.to_dict()
            indicators.append(indicators_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "indicators": indicators,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bulk_indicator import BulkIndicator

        d = dict(src_dict)
        indicators = []
        _indicators = d.pop("indicators")
        for indicators_item_data in _indicators:
            indicators_item = BulkIndicator.from_dict(indicators_item_data)

            indicators.append(indicators_item)

        bulk_enrich_request = cls(
            indicators=indicators,
        )

        bulk_enrich_request.additional_properties = d
        return bulk_enrich_request

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
