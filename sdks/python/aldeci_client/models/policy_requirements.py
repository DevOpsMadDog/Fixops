from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PolicyRequirements")


@_attrs_define
class PolicyRequirements:
    """
    Attributes:
        min_os_version (str | Unset):  Default: ''.
        require_encryption (bool | Unset):  Default: True.
        require_passcode (bool | Unset):  Default: True.
        allowed_apps (list[str] | Unset):
    """

    min_os_version: str | Unset = ""
    require_encryption: bool | Unset = True
    require_passcode: bool | Unset = True
    allowed_apps: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        min_os_version = self.min_os_version

        require_encryption = self.require_encryption

        require_passcode = self.require_passcode

        allowed_apps: list[str] | Unset = UNSET
        if not isinstance(self.allowed_apps, Unset):
            allowed_apps = self.allowed_apps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if min_os_version is not UNSET:
            field_dict["min_os_version"] = min_os_version
        if require_encryption is not UNSET:
            field_dict["require_encryption"] = require_encryption
        if require_passcode is not UNSET:
            field_dict["require_passcode"] = require_passcode
        if allowed_apps is not UNSET:
            field_dict["allowed_apps"] = allowed_apps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        min_os_version = d.pop("min_os_version", UNSET)

        require_encryption = d.pop("require_encryption", UNSET)

        require_passcode = d.pop("require_passcode", UNSET)

        allowed_apps = cast(list[str], d.pop("allowed_apps", UNSET))

        policy_requirements = cls(
            min_os_version=min_os_version,
            require_encryption=require_encryption,
            require_passcode=require_passcode,
            allowed_apps=allowed_apps,
        )

        policy_requirements.additional_properties = d
        return policy_requirements

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
