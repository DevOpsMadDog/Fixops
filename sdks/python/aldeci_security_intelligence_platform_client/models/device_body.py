from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeviceBody")


@_attrs_define
class DeviceBody:
    """
    Attributes:
        device_name (str | Unset):  Default: 'Unknown Device'.
        platform (str | Unset):  Default: 'android'.
        os_version (str | Unset):  Default: ''.
        enrollment_status (str | Unset):  Default: 'pending'.
        compliance_status (str | Unset):  Default: 'unknown'.
        risk_score (int | Unset):  Default: 0.
        jailbroken (bool | Unset):  Default: False.
        last_checkin (None | str | Unset):
    """

    device_name: str | Unset = "Unknown Device"
    platform: str | Unset = "android"
    os_version: str | Unset = ""
    enrollment_status: str | Unset = "pending"
    compliance_status: str | Unset = "unknown"
    risk_score: int | Unset = 0
    jailbroken: bool | Unset = False
    last_checkin: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        device_name = self.device_name

        platform = self.platform

        os_version = self.os_version

        enrollment_status = self.enrollment_status

        compliance_status = self.compliance_status

        risk_score = self.risk_score

        jailbroken = self.jailbroken

        last_checkin: None | str | Unset
        if isinstance(self.last_checkin, Unset):
            last_checkin = UNSET
        else:
            last_checkin = self.last_checkin

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if device_name is not UNSET:
            field_dict["device_name"] = device_name
        if platform is not UNSET:
            field_dict["platform"] = platform
        if os_version is not UNSET:
            field_dict["os_version"] = os_version
        if enrollment_status is not UNSET:
            field_dict["enrollment_status"] = enrollment_status
        if compliance_status is not UNSET:
            field_dict["compliance_status"] = compliance_status
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if jailbroken is not UNSET:
            field_dict["jailbroken"] = jailbroken
        if last_checkin is not UNSET:
            field_dict["last_checkin"] = last_checkin

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        device_name = d.pop("device_name", UNSET)

        platform = d.pop("platform", UNSET)

        os_version = d.pop("os_version", UNSET)

        enrollment_status = d.pop("enrollment_status", UNSET)

        compliance_status = d.pop("compliance_status", UNSET)

        risk_score = d.pop("risk_score", UNSET)

        jailbroken = d.pop("jailbroken", UNSET)

        def _parse_last_checkin(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_checkin = _parse_last_checkin(d.pop("last_checkin", UNSET))

        device_body = cls(
            device_name=device_name,
            platform=platform,
            os_version=os_version,
            enrollment_status=enrollment_status,
            compliance_status=compliance_status,
            risk_score=risk_score,
            jailbroken=jailbroken,
            last_checkin=last_checkin,
        )

        device_body.additional_properties = d
        return device_body

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
