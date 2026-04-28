from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrollDeviceRequest")


@_attrs_define
class EnrollDeviceRequest:
    """
    Attributes:
        name (str): Device display name
        platform (str): Device platform: ios/android/windows/macos
        org_id (str | Unset): Organisation identifier Default: 'default'.
        serial_number (str | Unset): Device serial number Default: ''.
        os_version (str | Unset): Operating system version Default: ''.
    """

    name: str
    platform: str
    org_id: str | Unset = "default"
    serial_number: str | Unset = ""
    os_version: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        platform = self.platform

        org_id = self.org_id

        serial_number = self.serial_number

        os_version = self.os_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "platform": platform,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if serial_number is not UNSET:
            field_dict["serial_number"] = serial_number
        if os_version is not UNSET:
            field_dict["os_version"] = os_version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        platform = d.pop("platform")

        org_id = d.pop("org_id", UNSET)

        serial_number = d.pop("serial_number", UNSET)

        os_version = d.pop("os_version", UNSET)

        enroll_device_request = cls(
            name=name,
            platform=platform,
            org_id=org_id,
            serial_number=serial_number,
            os_version=os_version,
        )

        enroll_device_request.additional_properties = d
        return enroll_device_request

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
