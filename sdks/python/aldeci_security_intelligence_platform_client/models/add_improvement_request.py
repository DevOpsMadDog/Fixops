from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddImprovementRequest")


@_attrs_define
class AddImprovementRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        improvement_name (str): Name of the improvement initiative
        priority (str | Unset): Priority: critical/high/medium/low Default: 'medium'.
        target_level (int | Unset): Target maturity level Default: 3.
        effort_days (int | Unset): Estimated effort in days Default: 0.
        due_date (str | Unset): ISO-8601 due date Default: ''.
    """

    org_id: str
    improvement_name: str
    priority: str | Unset = "medium"
    target_level: int | Unset = 3
    effort_days: int | Unset = 0
    due_date: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        improvement_name = self.improvement_name

        priority = self.priority

        target_level = self.target_level

        effort_days = self.effort_days

        due_date = self.due_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "improvement_name": improvement_name,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority
        if target_level is not UNSET:
            field_dict["target_level"] = target_level
        if effort_days is not UNSET:
            field_dict["effort_days"] = effort_days
        if due_date is not UNSET:
            field_dict["due_date"] = due_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        improvement_name = d.pop("improvement_name")

        priority = d.pop("priority", UNSET)

        target_level = d.pop("target_level", UNSET)

        effort_days = d.pop("effort_days", UNSET)

        due_date = d.pop("due_date", UNSET)

        add_improvement_request = cls(
            org_id=org_id,
            improvement_name=improvement_name,
            priority=priority,
            target_level=target_level,
            effort_days=effort_days,
            due_date=due_date,
        )

        add_improvement_request.additional_properties = d
        return add_improvement_request

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
