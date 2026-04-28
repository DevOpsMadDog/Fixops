from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.regulatory_status_response import RegulatoryStatusResponse


T = TypeVar("T", bound="RegulatoryHeatmapResponse")


@_attrs_define
class RegulatoryHeatmapResponse:
    """Full regulatory risk heatmap.

    Attributes:
        regulations (list[RegulatoryStatusResponse]):
        total_estimated_exposure_usd (float):
        red_count (int):
        yellow_count (int):
        green_count (int):
        computed_at (datetime.datetime):
    """

    regulations: list[RegulatoryStatusResponse]
    total_estimated_exposure_usd: float
    red_count: int
    yellow_count: int
    green_count: int
    computed_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        regulations = []
        for regulations_item_data in self.regulations:
            regulations_item = regulations_item_data.to_dict()
            regulations.append(regulations_item)

        total_estimated_exposure_usd = self.total_estimated_exposure_usd

        red_count = self.red_count

        yellow_count = self.yellow_count

        green_count = self.green_count

        computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "regulations": regulations,
                "total_estimated_exposure_usd": total_estimated_exposure_usd,
                "red_count": red_count,
                "yellow_count": yellow_count,
                "green_count": green_count,
                "computed_at": computed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.regulatory_status_response import RegulatoryStatusResponse

        d = dict(src_dict)
        regulations = []
        _regulations = d.pop("regulations")
        for regulations_item_data in _regulations:
            regulations_item = RegulatoryStatusResponse.from_dict(regulations_item_data)

            regulations.append(regulations_item)

        total_estimated_exposure_usd = d.pop("total_estimated_exposure_usd")

        red_count = d.pop("red_count")

        yellow_count = d.pop("yellow_count")

        green_count = d.pop("green_count")

        computed_at = isoparse(d.pop("computed_at"))

        regulatory_heatmap_response = cls(
            regulations=regulations,
            total_estimated_exposure_usd=total_estimated_exposure_usd,
            red_count=red_count,
            yellow_count=yellow_count,
            green_count=green_count,
            computed_at=computed_at,
        )

        regulatory_heatmap_response.additional_properties = d
        return regulatory_heatmap_response

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
