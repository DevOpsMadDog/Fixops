from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TrendPoint")


@_attrs_define
class TrendPoint:
    """A single point in a vulnerability trend time-series.

    Attributes:
        date (str): ISO date string for the bucket (YYYY-MM-DD)
        new_count (int | Unset): Findings opened during the period Default: 0.
        resolved_count (int | Unset): Findings resolved during the period Default: 0.
        reopened_count (int | Unset): Findings reopened during the period Default: 0.
        total_open (int | Unset): Total open findings at end of period Default: 0.
    """

    date: str
    new_count: int | Unset = 0
    resolved_count: int | Unset = 0
    reopened_count: int | Unset = 0
    total_open: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        date = self.date

        new_count = self.new_count

        resolved_count = self.resolved_count

        reopened_count = self.reopened_count

        total_open = self.total_open

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "date": date,
            }
        )
        if new_count is not UNSET:
            field_dict["new_count"] = new_count
        if resolved_count is not UNSET:
            field_dict["resolved_count"] = resolved_count
        if reopened_count is not UNSET:
            field_dict["reopened_count"] = reopened_count
        if total_open is not UNSET:
            field_dict["total_open"] = total_open

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        date = d.pop("date")

        new_count = d.pop("new_count", UNSET)

        resolved_count = d.pop("resolved_count", UNSET)

        reopened_count = d.pop("reopened_count", UNSET)

        total_open = d.pop("total_open", UNSET)

        trend_point = cls(
            date=date,
            new_count=new_count,
            resolved_count=resolved_count,
            reopened_count=reopened_count,
            total_open=total_open,
        )

        trend_point.additional_properties = d
        return trend_point

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
