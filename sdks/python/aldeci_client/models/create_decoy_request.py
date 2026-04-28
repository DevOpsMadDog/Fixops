from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateDecoyRequest")


@_attrs_define
class CreateDecoyRequest:
    """
    Attributes:
        name (str): Human-readable decoy name
        decoy_type (str | Unset): honeypot | honeytoken | honeydoc | fake_service | canary_endpoint Default: 'honeypot'.
        ip_address (str | Unset): Decoy IP address Default: ''.
        port (int | Unset): Decoy port number Default: 0.
        description (str | Unset):  Default: ''.
        active (bool | Unset):  Default: True.
    """

    name: str
    decoy_type: str | Unset = "honeypot"
    ip_address: str | Unset = ""
    port: int | Unset = 0
    description: str | Unset = ""
    active: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        decoy_type = self.decoy_type

        ip_address = self.ip_address

        port = self.port

        description = self.description

        active = self.active

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if decoy_type is not UNSET:
            field_dict["decoy_type"] = decoy_type
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if port is not UNSET:
            field_dict["port"] = port
        if description is not UNSET:
            field_dict["description"] = description
        if active is not UNSET:
            field_dict["active"] = active

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        decoy_type = d.pop("decoy_type", UNSET)

        ip_address = d.pop("ip_address", UNSET)

        port = d.pop("port", UNSET)

        description = d.pop("description", UNSET)

        active = d.pop("active", UNSET)

        create_decoy_request = cls(
            name=name,
            decoy_type=decoy_type,
            ip_address=ip_address,
            port=port,
            description=description,
            active=active,
        )

        create_decoy_request.additional_properties = d
        return create_decoy_request

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
