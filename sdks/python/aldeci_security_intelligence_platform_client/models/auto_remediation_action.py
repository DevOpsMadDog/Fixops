from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AutoRemediationAction")


@_attrs_define
class AutoRemediationAction:
    """
    Attributes:
        id (str):
        trigger (str):
        action_type (str):
        target (str):
        severity (str):
        status (str):
        confidence (float):
        timestamp (str):
    """

    id: str
    trigger: str
    action_type: str
    target: str
    severity: str
    status: str
    confidence: float
    timestamp: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        trigger = self.trigger

        action_type = self.action_type

        target = self.target

        severity = self.severity

        status = self.status

        confidence = self.confidence

        timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "trigger": trigger,
                "action_type": action_type,
                "target": target,
                "severity": severity,
                "status": status,
                "confidence": confidence,
                "timestamp": timestamp,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        trigger = d.pop("trigger")

        action_type = d.pop("action_type")

        target = d.pop("target")

        severity = d.pop("severity")

        status = d.pop("status")

        confidence = d.pop("confidence")

        timestamp = d.pop("timestamp")

        auto_remediation_action = cls(
            id=id,
            trigger=trigger,
            action_type=action_type,
            target=target,
            severity=severity,
            status=status,
            confidence=confidence,
            timestamp=timestamp,
        )

        auto_remediation_action.additional_properties = d
        return auto_remediation_action

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
