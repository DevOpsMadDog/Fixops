from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatBody")


@_attrs_define
class ThreatBody:
    """
    Attributes:
        device_id (str):
        threat_type (str | Unset):  Default: 'malware'.
        severity (str | Unset):  Default: 'medium'.
        description (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'active'.
    """

    device_id: str
    threat_type: str | Unset = "malware"
    severity: str | Unset = "medium"
    description: str | Unset = ""
    status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        device_id = self.device_id

        threat_type = self.threat_type

        severity = self.severity

        description = self.description

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "device_id": device_id,
            }
        )
        if threat_type is not UNSET:
            field_dict["threat_type"] = threat_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        device_id = d.pop("device_id")

        threat_type = d.pop("threat_type", UNSET)

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        status = d.pop("status", UNSET)

        threat_body = cls(
            device_id=device_id,
            threat_type=threat_type,
            severity=severity,
            description=description,
            status=status,
        )

        threat_body.additional_properties = d
        return threat_body

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
