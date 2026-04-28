from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssignRemediationRequest")


@_attrs_define
class AssignRemediationRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        assignee (str): Assigned engineer/team
        due_date (str): ISO-8601 due date
        notes (str | Unset): Additional notes Default: ''.
    """

    org_id: str
    assignee: str
    due_date: str
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        assignee = self.assignee

        due_date = self.due_date

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "assignee": assignee,
                "due_date": due_date,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        assignee = d.pop("assignee")

        due_date = d.pop("due_date")

        notes = d.pop("notes", UNSET)

        assign_remediation_request = cls(
            org_id=org_id,
            assignee=assignee,
            due_date=due_date,
            notes=notes,
        )

        assign_remediation_request.additional_properties = d
        return assign_remediation_request

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
