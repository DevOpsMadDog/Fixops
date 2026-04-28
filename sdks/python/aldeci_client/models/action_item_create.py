from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ActionItemCreate")


@_attrs_define
class ActionItemCreate:
    """
    Attributes:
        action (str):
        due_date (str):
        owner (str | Unset):  Default: ''.
        priority (str | Unset):  Default: 'medium'.
    """

    action: str
    due_date: str
    owner: str | Unset = ""
    priority: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action = self.action

        due_date = self.due_date

        owner = self.owner

        priority = self.priority

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "action": action,
                "due_date": due_date,
            }
        )
        if owner is not UNSET:
            field_dict["owner"] = owner
        if priority is not UNSET:
            field_dict["priority"] = priority

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action = d.pop("action")

        due_date = d.pop("due_date")

        owner = d.pop("owner", UNSET)

        priority = d.pop("priority", UNSET)

        action_item_create = cls(
            action=action,
            due_date=due_date,
            owner=owner,
            priority=priority,
        )

        action_item_create.additional_properties = d
        return action_item_create

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
