from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RemediationPlanCreate")


@_attrs_define
class RemediationPlanCreate:
    """
    Attributes:
        assessment_id (str):
        control_id (str):
        priority (str | Unset): p1/p2/p3/p4 Default: 'p3'.
        assigned_team (str | Unset):  Default: ''.
        estimated_effort (str | Unset): low/medium/high Default: 'medium'.
        target_date (str | Unset):  Default: ''.
        notes (str | Unset):  Default: ''.
    """

    assessment_id: str
    control_id: str
    priority: str | Unset = "p3"
    assigned_team: str | Unset = ""
    estimated_effort: str | Unset = "medium"
    target_date: str | Unset = ""
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        assessment_id = self.assessment_id

        control_id = self.control_id

        priority = self.priority

        assigned_team = self.assigned_team

        estimated_effort = self.estimated_effort

        target_date = self.target_date

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "assessment_id": assessment_id,
                "control_id": control_id,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority
        if assigned_team is not UNSET:
            field_dict["assigned_team"] = assigned_team
        if estimated_effort is not UNSET:
            field_dict["estimated_effort"] = estimated_effort
        if target_date is not UNSET:
            field_dict["target_date"] = target_date
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        assessment_id = d.pop("assessment_id")

        control_id = d.pop("control_id")

        priority = d.pop("priority", UNSET)

        assigned_team = d.pop("assigned_team", UNSET)

        estimated_effort = d.pop("estimated_effort", UNSET)

        target_date = d.pop("target_date", UNSET)

        notes = d.pop("notes", UNSET)

        remediation_plan_create = cls(
            assessment_id=assessment_id,
            control_id=control_id,
            priority=priority,
            assigned_team=assigned_team,
            estimated_effort=estimated_effort,
            target_date=target_date,
            notes=notes,
        )

        remediation_plan_create.additional_properties = d
        return remediation_plan_create

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
