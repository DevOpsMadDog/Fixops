from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttributeCreate")


@_attrs_define
class AttributeCreate:
    """
    Attributes:
        attribute_name (str):
        attribute_value (str):
        verified (bool | Unset):  Default: False.
        source (str | Unset):  Default: ''.
    """

    attribute_name: str
    attribute_value: str
    verified: bool | Unset = False
    source: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        attribute_name = self.attribute_name

        attribute_value = self.attribute_value

        verified = self.verified

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "attribute_name": attribute_name,
                "attribute_value": attribute_value,
            }
        )
        if verified is not UNSET:
            field_dict["verified"] = verified
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        attribute_name = d.pop("attribute_name")

        attribute_value = d.pop("attribute_value")

        verified = d.pop("verified", UNSET)

        source = d.pop("source", UNSET)

        attribute_create = cls(
            attribute_name=attribute_name,
            attribute_value=attribute_value,
            verified=verified,
            source=source,
        )

        attribute_create.additional_properties = d
        return attribute_create

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
