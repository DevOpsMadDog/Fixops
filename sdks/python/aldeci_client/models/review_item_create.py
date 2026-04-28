from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReviewItemCreate")


@_attrs_define
class ReviewItemCreate:
    """
    Attributes:
        user_id (str):
        resource_id (str):
        resource_type (str | Unset):  Default: ''.
        access_level (str | Unset):  Default: ''.
    """

    user_id: str
    resource_id: str
    resource_type: str | Unset = ""
    access_level: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        resource_id = self.resource_id

        resource_type = self.resource_type

        access_level = self.access_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "resource_id": resource_id,
            }
        )
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if access_level is not UNSET:
            field_dict["access_level"] = access_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        resource_id = d.pop("resource_id")

        resource_type = d.pop("resource_type", UNSET)

        access_level = d.pop("access_level", UNSET)

        review_item_create = cls(
            user_id=user_id,
            resource_id=resource_id,
            resource_type=resource_type,
            access_level=access_level,
        )

        review_item_create.additional_properties = d
        return review_item_create

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
