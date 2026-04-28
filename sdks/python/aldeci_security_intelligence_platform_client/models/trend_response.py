from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.trend_snapshot_response import TrendSnapshotResponse


T = TypeVar("T", bound="TrendResponse")


@_attrs_define
class TrendResponse:
    """Risk trend data with snapshots and direction.

    Attributes:
        snapshots (list[TrendSnapshotResponse]):
        trend_direction (str):
        mttr_trend (str):
        weeks_analysed (int):
    """

    snapshots: list[TrendSnapshotResponse]
    trend_direction: str
    mttr_trend: str
    weeks_analysed: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        snapshots = []
        for snapshots_item_data in self.snapshots:
            snapshots_item = snapshots_item_data.to_dict()
            snapshots.append(snapshots_item)

        trend_direction = self.trend_direction

        mttr_trend = self.mttr_trend

        weeks_analysed = self.weeks_analysed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "snapshots": snapshots,
                "trend_direction": trend_direction,
                "mttr_trend": mttr_trend,
                "weeks_analysed": weeks_analysed,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.trend_snapshot_response import TrendSnapshotResponse

        d = dict(src_dict)
        snapshots = []
        _snapshots = d.pop("snapshots")
        for snapshots_item_data in _snapshots:
            snapshots_item = TrendSnapshotResponse.from_dict(snapshots_item_data)

            snapshots.append(snapshots_item)

        trend_direction = d.pop("trend_direction")

        mttr_trend = d.pop("mttr_trend")

        weeks_analysed = d.pop("weeks_analysed")

        trend_response = cls(
            snapshots=snapshots,
            trend_direction=trend_direction,
            mttr_trend=mttr_trend,
            weeks_analysed=weeks_analysed,
        )

        trend_response.additional_properties = d
        return trend_response

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
