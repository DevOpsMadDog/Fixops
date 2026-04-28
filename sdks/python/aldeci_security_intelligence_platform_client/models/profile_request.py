from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProfileRequest")


@_attrs_define
class ProfileRequest:
    """
    Attributes:
        name (str):
        standard (str | Unset):  Default: 'CIS'.
        target_type (str | Unset):  Default: 'linux_server'.
        version (str | Unset):  Default: '1.0'.
    """

    name: str
    standard: str | Unset = "CIS"
    target_type: str | Unset = "linux_server"
    version: str | Unset = "1.0"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        standard = self.standard

        target_type = self.target_type

        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if standard is not UNSET:
            field_dict["standard"] = standard
        if target_type is not UNSET:
            field_dict["target_type"] = target_type
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        standard = d.pop("standard", UNSET)

        target_type = d.pop("target_type", UNSET)

        version = d.pop("version", UNSET)

        profile_request = cls(
            name=name,
            standard=standard,
            target_type=target_type,
            version=version,
        )

        profile_request.additional_properties = d
        return profile_request

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
