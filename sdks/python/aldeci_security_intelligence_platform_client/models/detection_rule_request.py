from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectionRuleRequest")


@_attrs_define
class DetectionRuleRequest:
    """
    Attributes:
        org_id (str):
        name (str):
        pattern (str):
        severity (str | Unset):  Default: 'medium'.
        action (str | Unset):  Default: 'alert'.
    """

    org_id: str
    name: str
    pattern: str
    severity: str | Unset = "medium"
    action: str | Unset = "alert"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        name = self.name

        pattern = self.pattern

        severity = self.severity

        action = self.action

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "name": name,
                "pattern": pattern,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if action is not UNSET:
            field_dict["action"] = action

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        name = d.pop("name")

        pattern = d.pop("pattern")

        severity = d.pop("severity", UNSET)

        action = d.pop("action", UNSET)

        detection_rule_request = cls(
            org_id=org_id,
            name=name,
            pattern=pattern,
            severity=severity,
            action=action,
        )

        detection_rule_request.additional_properties = d
        return detection_rule_request

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
