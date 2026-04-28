from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BadgeCreate")


@_attrs_define
class BadgeCreate:
    """
    Attributes:
        badge_name (str):
        badge_type (str | Unset):  Default: 'achievement'.
        description (str | Unset):  Default: ''.
    """

    badge_name: str
    badge_type: str | Unset = "achievement"
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        badge_name = self.badge_name

        badge_type = self.badge_type

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "badge_name": badge_name,
            }
        )
        if badge_type is not UNSET:
            field_dict["badge_type"] = badge_type
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        badge_name = d.pop("badge_name")

        badge_type = d.pop("badge_type", UNSET)

        description = d.pop("description", UNSET)

        badge_create = cls(
            badge_name=badge_name,
            badge_type=badge_type,
            description=description,
        )

        badge_create.additional_properties = d
        return badge_create

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
