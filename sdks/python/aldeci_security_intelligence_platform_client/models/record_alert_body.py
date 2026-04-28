from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordAlertBody")


@_attrs_define
class RecordAlertBody:
    """
    Attributes:
        alert_type (str): suspicious_command | data_exfiltration | privilege_escalation | policy_violation | anomaly
        severity (str | Unset): critical | high | medium | low | info Default: 'medium'.
        description (str | Unset): Alert description Default: ''.
        command_context (str | Unset): Command or context that triggered the alert Default: ''.
    """

    alert_type: str
    severity: str | Unset = "medium"
    description: str | Unset = ""
    command_context: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        alert_type = self.alert_type

        severity = self.severity

        description = self.description

        command_context = self.command_context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "alert_type": alert_type,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if command_context is not UNSET:
            field_dict["command_context"] = command_context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        alert_type = d.pop("alert_type")

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        command_context = d.pop("command_context", UNSET)

        record_alert_body = cls(
            alert_type=alert_type,
            severity=severity,
            description=description,
            command_context=command_context,
        )

        record_alert_body.additional_properties = d
        return record_alert_body

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
