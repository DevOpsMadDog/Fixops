from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MDMPolicyBody")


@_attrs_define
class MDMPolicyBody:
    """
    Attributes:
        name (str | Unset):  Default: 'Default MDM Policy'.
        require_encryption (bool | Unset):  Default: True.
        require_pin (bool | Unset):  Default: True.
        min_os_version (str | Unset):  Default: ''.
        allow_jailbroken (bool | Unset):  Default: False.
        remote_wipe_enabled (bool | Unset):  Default: False.
    """

    name: str | Unset = "Default MDM Policy"
    require_encryption: bool | Unset = True
    require_pin: bool | Unset = True
    min_os_version: str | Unset = ""
    allow_jailbroken: bool | Unset = False
    remote_wipe_enabled: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        require_encryption = self.require_encryption

        require_pin = self.require_pin

        min_os_version = self.min_os_version

        allow_jailbroken = self.allow_jailbroken

        remote_wipe_enabled = self.remote_wipe_enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if require_encryption is not UNSET:
            field_dict["require_encryption"] = require_encryption
        if require_pin is not UNSET:
            field_dict["require_pin"] = require_pin
        if min_os_version is not UNSET:
            field_dict["min_os_version"] = min_os_version
        if allow_jailbroken is not UNSET:
            field_dict["allow_jailbroken"] = allow_jailbroken
        if remote_wipe_enabled is not UNSET:
            field_dict["remote_wipe_enabled"] = remote_wipe_enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name", UNSET)

        require_encryption = d.pop("require_encryption", UNSET)

        require_pin = d.pop("require_pin", UNSET)

        min_os_version = d.pop("min_os_version", UNSET)

        allow_jailbroken = d.pop("allow_jailbroken", UNSET)

        remote_wipe_enabled = d.pop("remote_wipe_enabled", UNSET)

        mdm_policy_body = cls(
            name=name,
            require_encryption=require_encryption,
            require_pin=require_pin,
            min_os_version=min_os_version,
            allow_jailbroken=allow_jailbroken,
            remote_wipe_enabled=remote_wipe_enabled,
        )

        mdm_policy_body.additional_properties = d
        return mdm_policy_body

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
