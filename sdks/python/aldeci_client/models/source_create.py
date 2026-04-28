from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SourceCreate")


@_attrs_define
class SourceCreate:
    """
    Attributes:
        source_name (str):
        source_type (str | Unset):  Default: 'custom'.
        endpoint_url (str | Unset):  Default: ''.
        active (bool | Unset):  Default: True.
    """

    source_name: str
    source_type: str | Unset = "custom"
    endpoint_url: str | Unset = ""
    active: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_name = self.source_name

        source_type = self.source_type

        endpoint_url = self.endpoint_url

        active = self.active

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_name": source_name,
            }
        )
        if source_type is not UNSET:
            field_dict["source_type"] = source_type
        if endpoint_url is not UNSET:
            field_dict["endpoint_url"] = endpoint_url
        if active is not UNSET:
            field_dict["active"] = active

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_name = d.pop("source_name")

        source_type = d.pop("source_type", UNSET)

        endpoint_url = d.pop("endpoint_url", UNSET)

        active = d.pop("active", UNSET)

        source_create = cls(
            source_name=source_name,
            source_type=source_type,
            endpoint_url=endpoint_url,
            active=active,
        )

        source_create.additional_properties = d
        return source_create

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
