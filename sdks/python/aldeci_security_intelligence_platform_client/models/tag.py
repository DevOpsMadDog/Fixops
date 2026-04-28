from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Tag")


@_attrs_define
class Tag:
    """
    Attributes:
        name (str):
        id (str | Unset):
        color (str | Unset): Hex color code Default: '#6B7280'.
        description (str | Unset):  Default: ''.
        parent_id (None | str | Unset):
        org_id (str | Unset):  Default: 'default'.
        created_at (str | Unset):
    """

    name: str
    id: str | Unset = UNSET
    color: str | Unset = "#6B7280"
    description: str | Unset = ""
    parent_id: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    created_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        id = self.id

        color = self.color

        description = self.description

        parent_id: None | str | Unset
        if isinstance(self.parent_id, Unset):
            parent_id = UNSET
        else:
            parent_id = self.parent_id

        org_id = self.org_id

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if color is not UNSET:
            field_dict["color"] = color
        if description is not UNSET:
            field_dict["description"] = description
        if parent_id is not UNSET:
            field_dict["parent_id"] = parent_id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        id = d.pop("id", UNSET)

        color = d.pop("color", UNSET)

        description = d.pop("description", UNSET)

        def _parse_parent_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        parent_id = _parse_parent_id(d.pop("parent_id", UNSET))

        org_id = d.pop("org_id", UNSET)

        created_at = d.pop("created_at", UNSET)

        tag = cls(
            name=name,
            id=id,
            color=color,
            description=description,
            parent_id=parent_id,
            org_id=org_id,
            created_at=created_at,
        )

        tag.additional_properties = d
        return tag

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
