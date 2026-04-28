from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.schedule_export_request_filters import ScheduleExportRequestFilters


T = TypeVar("T", bound="ScheduleExportRequest")


@_attrs_define
class ScheduleExportRequest:
    """
    Attributes:
        org_id (str):
        format_ (str | Unset):  Default: 'json'.
        filters (ScheduleExportRequestFilters | Unset):
        frequency (str | Unset): Frequency: hourly, daily, weekly Default: 'daily'.
    """

    org_id: str
    format_: str | Unset = "json"
    filters: ScheduleExportRequestFilters | Unset = UNSET
    frequency: str | Unset = "daily"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        format_ = self.format_

        filters: dict[str, Any] | Unset = UNSET
        if not isinstance(self.filters, Unset):
            filters = self.filters.to_dict()

        frequency = self.frequency

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if format_ is not UNSET:
            field_dict["format"] = format_
        if filters is not UNSET:
            field_dict["filters"] = filters
        if frequency is not UNSET:
            field_dict["frequency"] = frequency

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.schedule_export_request_filters import ScheduleExportRequestFilters

        d = dict(src_dict)
        org_id = d.pop("org_id")

        format_ = d.pop("format", UNSET)

        _filters = d.pop("filters", UNSET)
        filters: ScheduleExportRequestFilters | Unset
        if isinstance(_filters, Unset):
            filters = UNSET
        else:
            filters = ScheduleExportRequestFilters.from_dict(_filters)

        frequency = d.pop("frequency", UNSET)

        schedule_export_request = cls(
            org_id=org_id,
            format_=format_,
            filters=filters,
            frequency=frequency,
        )

        schedule_export_request.additional_properties = d
        return schedule_export_request

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
