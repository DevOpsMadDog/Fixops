from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TagCreate")


@_attrs_define
class TagCreate:
    """
    Attributes:
        tag_key (str): Tag key (e.g. 'env', 'team')
        tag_value (str): Tag value (e.g. 'production', 'security')
        tag_category (str | Unset): environment | criticality | data_classification | owner | compliance | technology |
            location | department Default: 'environment'.
        description (str | Unset):  Default: ''.
    """

    tag_key: str
    tag_value: str
    tag_category: str | Unset = "environment"
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tag_key = self.tag_key

        tag_value = self.tag_value

        tag_category = self.tag_category

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tag_key": tag_key,
                "tag_value": tag_value,
            }
        )
        if tag_category is not UNSET:
            field_dict["tag_category"] = tag_category
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tag_key = d.pop("tag_key")

        tag_value = d.pop("tag_value")

        tag_category = d.pop("tag_category", UNSET)

        description = d.pop("description", UNSET)

        tag_create = cls(
            tag_key=tag_key,
            tag_value=tag_value,
            tag_category=tag_category,
            description=description,
        )

        tag_create.additional_properties = d
        return tag_create

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
