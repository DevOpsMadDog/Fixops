from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BreachItem")


@_attrs_define
class BreachItem:
    """
    Attributes:
        finding_id (str):
        severity (str):
        deadline (str):
        hours_past_deadline (float):
        recommended_actions (list[str]):
    """

    finding_id: str
    severity: str
    deadline: str
    hours_past_deadline: float
    recommended_actions: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        severity = self.severity

        deadline = self.deadline

        hours_past_deadline = self.hours_past_deadline

        recommended_actions = self.recommended_actions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "severity": severity,
                "deadline": deadline,
                "hours_past_deadline": hours_past_deadline,
                "recommended_actions": recommended_actions,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        severity = d.pop("severity")

        deadline = d.pop("deadline")

        hours_past_deadline = d.pop("hours_past_deadline")

        recommended_actions = cast(list[str], d.pop("recommended_actions"))

        breach_item = cls(
            finding_id=finding_id,
            severity=severity,
            deadline=deadline,
            hours_past_deadline=hours_past_deadline,
            recommended_actions=recommended_actions,
        )

        breach_item.additional_properties = d
        return breach_item

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
