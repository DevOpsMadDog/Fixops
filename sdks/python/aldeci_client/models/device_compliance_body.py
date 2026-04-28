from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeviceComplianceBody")


@_attrs_define
class DeviceComplianceBody:
    """
    Attributes:
        compliance_status (None | str | Unset):
        risk_score (int | None | Unset):
        jailbroken (bool | None | Unset):
        os_version (None | str | Unset):
        enrollment_status (None | str | Unset):
        last_checkin (None | str | Unset):
    """

    compliance_status: None | str | Unset = UNSET
    risk_score: int | None | Unset = UNSET
    jailbroken: bool | None | Unset = UNSET
    os_version: None | str | Unset = UNSET
    enrollment_status: None | str | Unset = UNSET
    last_checkin: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        compliance_status: None | str | Unset
        if isinstance(self.compliance_status, Unset):
            compliance_status = UNSET
        else:
            compliance_status = self.compliance_status

        risk_score: int | None | Unset
        if isinstance(self.risk_score, Unset):
            risk_score = UNSET
        else:
            risk_score = self.risk_score

        jailbroken: bool | None | Unset
        if isinstance(self.jailbroken, Unset):
            jailbroken = UNSET
        else:
            jailbroken = self.jailbroken

        os_version: None | str | Unset
        if isinstance(self.os_version, Unset):
            os_version = UNSET
        else:
            os_version = self.os_version

        enrollment_status: None | str | Unset
        if isinstance(self.enrollment_status, Unset):
            enrollment_status = UNSET
        else:
            enrollment_status = self.enrollment_status

        last_checkin: None | str | Unset
        if isinstance(self.last_checkin, Unset):
            last_checkin = UNSET
        else:
            last_checkin = self.last_checkin

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if compliance_status is not UNSET:
            field_dict["compliance_status"] = compliance_status
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if jailbroken is not UNSET:
            field_dict["jailbroken"] = jailbroken
        if os_version is not UNSET:
            field_dict["os_version"] = os_version
        if enrollment_status is not UNSET:
            field_dict["enrollment_status"] = enrollment_status
        if last_checkin is not UNSET:
            field_dict["last_checkin"] = last_checkin

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_compliance_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        compliance_status = _parse_compliance_status(d.pop("compliance_status", UNSET))

        def _parse_risk_score(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        risk_score = _parse_risk_score(d.pop("risk_score", UNSET))

        def _parse_jailbroken(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        jailbroken = _parse_jailbroken(d.pop("jailbroken", UNSET))

        def _parse_os_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        os_version = _parse_os_version(d.pop("os_version", UNSET))

        def _parse_enrollment_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        enrollment_status = _parse_enrollment_status(d.pop("enrollment_status", UNSET))

        def _parse_last_checkin(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_checkin = _parse_last_checkin(d.pop("last_checkin", UNSET))

        device_compliance_body = cls(
            compliance_status=compliance_status,
            risk_score=risk_score,
            jailbroken=jailbroken,
            os_version=os_version,
            enrollment_status=enrollment_status,
            last_checkin=last_checkin,
        )

        device_compliance_body.additional_properties = d
        return device_compliance_body

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
