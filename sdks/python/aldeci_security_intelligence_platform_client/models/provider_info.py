from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ProviderInfo")


@_attrs_define
class ProviderInfo:
    """
    Attributes:
        name (str):
        provider_type (str):
        enabled (bool):
        login_url (str):
    """

    name: str
    provider_type: str
    enabled: bool
    login_url: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        provider_type = self.provider_type

        enabled = self.enabled

        login_url = self.login_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "provider_type": provider_type,
                "enabled": enabled,
                "login_url": login_url,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        provider_type = d.pop("provider_type")

        enabled = d.pop("enabled")

        login_url = d.pop("login_url")

        provider_info = cls(
            name=name,
            provider_type=provider_type,
            enabled=enabled,
            login_url=login_url,
        )

        provider_info.additional_properties = d
        return provider_info

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
