from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EventRecord")


@_attrs_define
class EventRecord:
    """
    Attributes:
        event_type (str):
        event_date (str):
        description (str | Unset):  Default: ''.
        affected_users (int | Unset):  Default: 0.
        department (str | Unset):  Default: ''.
        response_action (str | Unset):  Default: ''.
    """

    event_type: str
    event_date: str
    description: str | Unset = ""
    affected_users: int | Unset = 0
    department: str | Unset = ""
    response_action: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type

        event_date = self.event_date

        description = self.description

        affected_users = self.affected_users

        department = self.department

        response_action = self.response_action

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_type": event_type,
                "event_date": event_date,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if affected_users is not UNSET:
            field_dict["affected_users"] = affected_users
        if department is not UNSET:
            field_dict["department"] = department
        if response_action is not UNSET:
            field_dict["response_action"] = response_action

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_type = d.pop("event_type")

        event_date = d.pop("event_date")

        description = d.pop("description", UNSET)

        affected_users = d.pop("affected_users", UNSET)

        department = d.pop("department", UNSET)

        response_action = d.pop("response_action", UNSET)

        event_record = cls(
            event_type=event_type,
            event_date=event_date,
            description=description,
            affected_users=affected_users,
            department=department,
            response_action=response_action,
        )

        event_record.additional_properties = d
        return event_record

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
