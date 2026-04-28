from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAutomationRuleRequest")


@_attrs_define
class CreateAutomationRuleRequest:
    """
    Attributes:
        rule_name (str): Human-readable rule name
        trigger_condition (str | Unset): Trigger condition expression Default: ''.
        action_type (str | Unset): auto_close | escalate | enrich | notify | block | isolate Default: 'notify'.
        confidence_threshold (float | Unset):  Default: 80.0.
        enabled (bool | Unset):  Default: True.
    """

    rule_name: str
    trigger_condition: str | Unset = ""
    action_type: str | Unset = "notify"
    confidence_threshold: float | Unset = 80.0
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_name = self.rule_name

        trigger_condition = self.trigger_condition

        action_type = self.action_type

        confidence_threshold = self.confidence_threshold

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_name": rule_name,
            }
        )
        if trigger_condition is not UNSET:
            field_dict["trigger_condition"] = trigger_condition
        if action_type is not UNSET:
            field_dict["action_type"] = action_type
        if confidence_threshold is not UNSET:
            field_dict["confidence_threshold"] = confidence_threshold
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_name = d.pop("rule_name")

        trigger_condition = d.pop("trigger_condition", UNSET)

        action_type = d.pop("action_type", UNSET)

        confidence_threshold = d.pop("confidence_threshold", UNSET)

        enabled = d.pop("enabled", UNSET)

        create_automation_rule_request = cls(
            rule_name=rule_name,
            trigger_condition=trigger_condition,
            action_type=action_type,
            confidence_threshold=confidence_threshold,
            enabled=enabled,
        )

        create_automation_rule_request.additional_properties = d
        return create_automation_rule_request

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
