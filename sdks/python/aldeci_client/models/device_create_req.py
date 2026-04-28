from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeviceCreateReq")


@_attrs_define
class DeviceCreateReq:
    """
    Attributes:
        org_id (str):
        hostname (str):
        device_type (str | Unset):  Default: 'laptop'.
        owner (None | str | Unset):
        ip_address (None | str | Unset):
        mac_address (None | str | Unset):
        os_type (None | str | Unset):
    """

    org_id: str
    hostname: str
    device_type: str | Unset = "laptop"
    owner: None | str | Unset = UNSET
    ip_address: None | str | Unset = UNSET
    mac_address: None | str | Unset = UNSET
    os_type: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        hostname = self.hostname

        device_type = self.device_type

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

        ip_address: None | str | Unset
        if isinstance(self.ip_address, Unset):
            ip_address = UNSET
        else:
            ip_address = self.ip_address

        mac_address: None | str | Unset
        if isinstance(self.mac_address, Unset):
            mac_address = UNSET
        else:
            mac_address = self.mac_address

        os_type: None | str | Unset
        if isinstance(self.os_type, Unset):
            os_type = UNSET
        else:
            os_type = self.os_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "hostname": hostname,
            }
        )
        if device_type is not UNSET:
            field_dict["device_type"] = device_type
        if owner is not UNSET:
            field_dict["owner"] = owner
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if mac_address is not UNSET:
            field_dict["mac_address"] = mac_address
        if os_type is not UNSET:
            field_dict["os_type"] = os_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        hostname = d.pop("hostname")

        device_type = d.pop("device_type", UNSET)

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        def _parse_ip_address(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ip_address = _parse_ip_address(d.pop("ip_address", UNSET))

        def _parse_mac_address(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        mac_address = _parse_mac_address(d.pop("mac_address", UNSET))

        def _parse_os_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        os_type = _parse_os_type(d.pop("os_type", UNSET))

        device_create_req = cls(
            org_id=org_id,
            hostname=hostname,
            device_type=device_type,
            owner=owner,
            ip_address=ip_address,
            mac_address=mac_address,
            os_type=os_type,
        )

        device_create_req.additional_properties = d
        return device_create_req

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
