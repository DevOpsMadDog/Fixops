from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterRegistryRequest")


@_attrs_define
class RegisterRegistryRequest:
    """
    Attributes:
        name (str): Registry display name
        url (str | Unset): Registry URL (e.g. registry.example.com) Default: ''.
        registry_type (str | Unset): One of: docker, ecr, gcr, acr, harbor Default: 'docker'.
        auth_configured (bool | Unset): Whether auth credentials are configured Default: False.
    """

    name: str
    url: str | Unset = ""
    registry_type: str | Unset = "docker"
    auth_configured: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        url = self.url

        registry_type = self.registry_type

        auth_configured = self.auth_configured

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if url is not UNSET:
            field_dict["url"] = url
        if registry_type is not UNSET:
            field_dict["registry_type"] = registry_type
        if auth_configured is not UNSET:
            field_dict["auth_configured"] = auth_configured

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        url = d.pop("url", UNSET)

        registry_type = d.pop("registry_type", UNSET)

        auth_configured = d.pop("auth_configured", UNSET)

        register_registry_request = cls(
            name=name,
            url=url,
            registry_type=registry_type,
            auth_configured=auth_configured,
        )

        register_registry_request.additional_properties = d
        return register_registry_request

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
