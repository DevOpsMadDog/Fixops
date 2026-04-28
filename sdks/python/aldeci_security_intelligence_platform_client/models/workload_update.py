from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="WorkloadUpdate")


@_attrs_define
class WorkloadUpdate:
    """
    Attributes:
        org_id (str):
        analyst_name (str):
        date (str):
        alerts_assigned (int | Unset):  Default: 0.
        alerts_resolved (int | Unset):  Default: 0.
        avg_resolution_mins (float | Unset):  Default: 0.0.
    """

    org_id: str
    analyst_name: str
    date: str
    alerts_assigned: int | Unset = 0
    alerts_resolved: int | Unset = 0
    avg_resolution_mins: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        analyst_name = self.analyst_name

        date = self.date

        alerts_assigned = self.alerts_assigned

        alerts_resolved = self.alerts_resolved

        avg_resolution_mins = self.avg_resolution_mins

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "analyst_name": analyst_name,
                "date": date,
            }
        )
        if alerts_assigned is not UNSET:
            field_dict["alerts_assigned"] = alerts_assigned
        if alerts_resolved is not UNSET:
            field_dict["alerts_resolved"] = alerts_resolved
        if avg_resolution_mins is not UNSET:
            field_dict["avg_resolution_mins"] = avg_resolution_mins

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        analyst_name = d.pop("analyst_name")

        date = d.pop("date")

        alerts_assigned = d.pop("alerts_assigned", UNSET)

        alerts_resolved = d.pop("alerts_resolved", UNSET)

        avg_resolution_mins = d.pop("avg_resolution_mins", UNSET)

        workload_update = cls(
            org_id=org_id,
            analyst_name=analyst_name,
            date=date,
            alerts_assigned=alerts_assigned,
            alerts_resolved=alerts_resolved,
            avg_resolution_mins=avg_resolution_mins,
        )

        workload_update.additional_properties = d
        return workload_update

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
