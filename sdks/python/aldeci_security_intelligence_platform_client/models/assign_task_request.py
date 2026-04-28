from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssignTaskRequest")


@_attrs_define
class AssignTaskRequest:
    """Request to assign task.

    Attributes:
        assignee (str):
        assignee_email (None | str | Unset):
        changed_by (None | str | Unset):
    """

    assignee: str
    assignee_email: None | str | Unset = UNSET
    changed_by: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        assignee = self.assignee

        assignee_email: None | str | Unset
        if isinstance(self.assignee_email, Unset):
            assignee_email = UNSET
        else:
            assignee_email = self.assignee_email

        changed_by: None | str | Unset
        if isinstance(self.changed_by, Unset):
            changed_by = UNSET
        else:
            changed_by = self.changed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "assignee": assignee,
            }
        )
        if assignee_email is not UNSET:
            field_dict["assignee_email"] = assignee_email
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        assignee = d.pop("assignee")

        def _parse_assignee_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee_email = _parse_assignee_email(d.pop("assignee_email", UNSET))

        def _parse_changed_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        changed_by = _parse_changed_by(d.pop("changed_by", UNSET))

        assign_task_request = cls(
            assignee=assignee,
            assignee_email=assignee_email,
            changed_by=changed_by,
        )

        assign_task_request.additional_properties = d
        return assign_task_request

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
