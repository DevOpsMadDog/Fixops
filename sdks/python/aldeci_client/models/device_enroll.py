from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeviceEnroll")


@_attrs_define
class DeviceEnroll:
    """
    Attributes:
        device_name (str | Unset):  Default: ''.
        platform (str | Unset):  Default: 'ios'.
        model (str | Unset):  Default: ''.
        serial_number (str | Unset):  Default: ''.
        owner_email (str | Unset):  Default: ''.
        enrollment_type (str | Unset):  Default: 'corporate'.
        os_version (str | Unset):  Default: ''.
    """

    device_name: str | Unset = ""
    platform: str | Unset = "ios"
    model: str | Unset = ""
    serial_number: str | Unset = ""
    owner_email: str | Unset = ""
    enrollment_type: str | Unset = "corporate"
    os_version: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        device_name = self.device_name

        platform = self.platform

        model = self.model

        serial_number = self.serial_number

        owner_email = self.owner_email

        enrollment_type = self.enrollment_type

        os_version = self.os_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if device_name is not UNSET:
            field_dict["device_name"] = device_name
        if platform is not UNSET:
            field_dict["platform"] = platform
        if model is not UNSET:
            field_dict["model"] = model
        if serial_number is not UNSET:
            field_dict["serial_number"] = serial_number
        if owner_email is not UNSET:
            field_dict["owner_email"] = owner_email
        if enrollment_type is not UNSET:
            field_dict["enrollment_type"] = enrollment_type
        if os_version is not UNSET:
            field_dict["os_version"] = os_version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        device_name = d.pop("device_name", UNSET)

        platform = d.pop("platform", UNSET)

        model = d.pop("model", UNSET)

        serial_number = d.pop("serial_number", UNSET)

        owner_email = d.pop("owner_email", UNSET)

        enrollment_type = d.pop("enrollment_type", UNSET)

        os_version = d.pop("os_version", UNSET)

        device_enroll = cls(
            device_name=device_name,
            platform=platform,
            model=model,
            serial_number=serial_number,
            owner_email=owner_email,
            enrollment_type=enrollment_type,
            os_version=os_version,
        )

        device_enroll.additional_properties = d
        return device_enroll

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
