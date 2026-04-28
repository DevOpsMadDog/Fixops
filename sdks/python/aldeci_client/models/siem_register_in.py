from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SIEMRegisterIn")


@_attrs_define
class SIEMRegisterIn:
    """
    Attributes:
        siem_name (str | Unset):  Default: ''.
        siem_type (str | Unset):  Default: 'generic'.
        host (str | Unset):  Default: ''.
        port (int | Unset):  Default: 0.
        api_token (str | Unset):  Default: ''.
        enabled (bool | Unset):  Default: True.
        index_name (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    siem_name: str | Unset = ""
    siem_type: str | Unset = "generic"
    host: str | Unset = ""
    port: int | Unset = 0
    api_token: str | Unset = ""
    enabled: bool | Unset = True
    index_name: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        siem_name = self.siem_name

        siem_type = self.siem_type

        host = self.host

        port = self.port

        api_token = self.api_token

        enabled = self.enabled

        index_name = self.index_name

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if siem_name is not UNSET:
            field_dict["siem_name"] = siem_name
        if siem_type is not UNSET:
            field_dict["siem_type"] = siem_type
        if host is not UNSET:
            field_dict["host"] = host
        if port is not UNSET:
            field_dict["port"] = port
        if api_token is not UNSET:
            field_dict["api_token"] = api_token
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if index_name is not UNSET:
            field_dict["index_name"] = index_name
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        siem_name = d.pop("siem_name", UNSET)

        siem_type = d.pop("siem_type", UNSET)

        host = d.pop("host", UNSET)

        port = d.pop("port", UNSET)

        api_token = d.pop("api_token", UNSET)

        enabled = d.pop("enabled", UNSET)

        index_name = d.pop("index_name", UNSET)

        org_id = d.pop("org_id", UNSET)

        siem_register_in = cls(
            siem_name=siem_name,
            siem_type=siem_type,
            host=host,
            port=port,
            api_token=api_token,
            enabled=enabled,
            index_name=index_name,
            org_id=org_id,
        )

        siem_register_in.additional_properties = d
        return siem_register_in

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
