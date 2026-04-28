from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ObligationCreate")


@_attrs_define
class ObligationCreate:
    """
    Attributes:
        reg_id (str):
        title (str):
        change_id (None | str | Unset):
        description (str | Unset):  Default: ''.
        obligation_type (str | Unset):  Default: 'technical'.
        deadline (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'pending'.
        owner (str | Unset):  Default: ''.
    """

    reg_id: str
    title: str
    change_id: None | str | Unset = UNSET
    description: str | Unset = ""
    obligation_type: str | Unset = "technical"
    deadline: str | Unset = ""
    status: str | Unset = "pending"
    owner: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        reg_id = self.reg_id

        title = self.title

        change_id: None | str | Unset
        if isinstance(self.change_id, Unset):
            change_id = UNSET
        else:
            change_id = self.change_id

        description = self.description

        obligation_type = self.obligation_type

        deadline = self.deadline

        status = self.status

        owner = self.owner

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "reg_id": reg_id,
                "title": title,
            }
        )
        if change_id is not UNSET:
            field_dict["change_id"] = change_id
        if description is not UNSET:
            field_dict["description"] = description
        if obligation_type is not UNSET:
            field_dict["obligation_type"] = obligation_type
        if deadline is not UNSET:
            field_dict["deadline"] = deadline
        if status is not UNSET:
            field_dict["status"] = status
        if owner is not UNSET:
            field_dict["owner"] = owner

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        reg_id = d.pop("reg_id")

        title = d.pop("title")

        def _parse_change_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        change_id = _parse_change_id(d.pop("change_id", UNSET))

        description = d.pop("description", UNSET)

        obligation_type = d.pop("obligation_type", UNSET)

        deadline = d.pop("deadline", UNSET)

        status = d.pop("status", UNSET)

        owner = d.pop("owner", UNSET)

        obligation_create = cls(
            reg_id=reg_id,
            title=title,
            change_id=change_id,
            description=description,
            obligation_type=obligation_type,
            deadline=deadline,
            status=status,
            owner=owner,
        )

        obligation_create.additional_properties = d
        return obligation_create

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
