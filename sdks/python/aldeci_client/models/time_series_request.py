from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TimeSeriesRequest")


@_attrs_define
class TimeSeriesRequest:
    """
    Attributes:
        entity_id (str): User or service ID
        metric_name (str): Metric to analyse
        window_hours (int | Unset): Analysis window in hours Default: 24.
        entity_type (str | Unset): Entity type Default: 'service'.
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    entity_id: str
    metric_name: str
    window_hours: int | Unset = 24
    entity_type: str | Unset = "service"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_id = self.entity_id

        metric_name = self.metric_name

        window_hours = self.window_hours

        entity_type = self.entity_type

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_id": entity_id,
                "metric_name": metric_name,
            }
        )
        if window_hours is not UNSET:
            field_dict["window_hours"] = window_hours
        if entity_type is not UNSET:
            field_dict["entity_type"] = entity_type
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entity_id = d.pop("entity_id")

        metric_name = d.pop("metric_name")

        window_hours = d.pop("window_hours", UNSET)

        entity_type = d.pop("entity_type", UNSET)

        org_id = d.pop("org_id", UNSET)

        time_series_request = cls(
            entity_id=entity_id,
            metric_name=metric_name,
            window_hours=window_hours,
            entity_type=entity_type,
            org_id=org_id,
        )

        time_series_request.additional_properties = d
        return time_series_request

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
