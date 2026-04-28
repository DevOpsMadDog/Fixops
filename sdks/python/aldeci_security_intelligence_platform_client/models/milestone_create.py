from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MilestoneCreate")


@_attrs_define
class MilestoneCreate:
    """
    Attributes:
        title (str):
        description (str | Unset):  Default: ''.
        due_date (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'pending'.
        completion_date (str | Unset):  Default: ''.
    """

    title: str
    description: str | Unset = ""
    due_date: str | Unset = ""
    status: str | Unset = "pending"
    completion_date: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        due_date = self.due_date

        status = self.status

        completion_date = self.completion_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if due_date is not UNSET:
            field_dict["due_date"] = due_date
        if status is not UNSET:
            field_dict["status"] = status
        if completion_date is not UNSET:
            field_dict["completion_date"] = completion_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description", UNSET)

        due_date = d.pop("due_date", UNSET)

        status = d.pop("status", UNSET)

        completion_date = d.pop("completion_date", UNSET)

        milestone_create = cls(
            title=title,
            description=description,
            due_date=due_date,
            status=status,
            completion_date=completion_date,
        )

        milestone_create.additional_properties = d
        return milestone_create

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
