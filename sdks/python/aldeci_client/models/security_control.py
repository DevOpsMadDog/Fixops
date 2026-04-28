from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SecurityControl")


@_attrs_define
class SecurityControl:
    """A security control with implementation status.

    Attributes:
        category (str):
        title (str):
        description (str):
        status (str):
        id (str | Unset):
        org_id (str | Unset):  Default: ''.
    """

    category: str
    title: str
    description: str
    status: str
    id: str | Unset = UNSET
    org_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        category = self.category

        title = self.title

        description = self.description

        status = self.status

        id = self.id

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "category": category,
                "title": title,
                "description": description,
                "status": status,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        category = d.pop("category")

        title = d.pop("title")

        description = d.pop("description")

        status = d.pop("status")

        id = d.pop("id", UNSET)

        org_id = d.pop("org_id", UNSET)

        security_control = cls(
            category=category,
            title=title,
            description=description,
            status=status,
            id=id,
            org_id=org_id,
        )

        security_control.additional_properties = d
        return security_control

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
