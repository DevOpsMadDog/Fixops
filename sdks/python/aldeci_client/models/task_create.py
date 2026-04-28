from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TaskCreate")


@_attrs_define
class TaskCreate:
    """
    Attributes:
        task_name (str):
        task_type (str | Unset):  Default: 'documentation'.
        assignee (str | Unset):  Default: ''.
        priority (str | Unset):  Default: 'medium'.
        evidence_required (int | Unset):  Default: 0.
        due_date (str | Unset):  Default: ''.
    """

    task_name: str
    task_type: str | Unset = "documentation"
    assignee: str | Unset = ""
    priority: str | Unset = "medium"
    evidence_required: int | Unset = 0
    due_date: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        task_name = self.task_name

        task_type = self.task_type

        assignee = self.assignee

        priority = self.priority

        evidence_required = self.evidence_required

        due_date = self.due_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "task_name": task_name,
            }
        )
        if task_type is not UNSET:
            field_dict["task_type"] = task_type
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if priority is not UNSET:
            field_dict["priority"] = priority
        if evidence_required is not UNSET:
            field_dict["evidence_required"] = evidence_required
        if due_date is not UNSET:
            field_dict["due_date"] = due_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        task_name = d.pop("task_name")

        task_type = d.pop("task_type", UNSET)

        assignee = d.pop("assignee", UNSET)

        priority = d.pop("priority", UNSET)

        evidence_required = d.pop("evidence_required", UNSET)

        due_date = d.pop("due_date", UNSET)

        task_create = cls(
            task_name=task_name,
            task_type=task_type,
            assignee=assignee,
            priority=priority,
            evidence_required=evidence_required,
            due_date=due_date,
        )

        task_create.additional_properties = d
        return task_create

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
