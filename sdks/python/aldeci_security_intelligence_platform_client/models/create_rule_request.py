from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateRuleRequest")


@_attrs_define
class CreateRuleRequest:
    """
    Attributes:
        rule_name (str):
        rule_type (str):
        action (str):
        threshold (float | Unset):  Default: 0.0.
        enabled (bool | Unset):  Default: True.
    """

    rule_name: str
    rule_type: str
    action: str
    threshold: float | Unset = 0.0
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_name = self.rule_name

        rule_type = self.rule_type

        action = self.action

        threshold = self.threshold

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_name": rule_name,
                "rule_type": rule_type,
                "action": action,
            }
        )
        if threshold is not UNSET:
            field_dict["threshold"] = threshold
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_name = d.pop("rule_name")

        rule_type = d.pop("rule_type")

        action = d.pop("action")

        threshold = d.pop("threshold", UNSET)

        enabled = d.pop("enabled", UNSET)

        create_rule_request = cls(
            rule_name=rule_name,
            rule_type=rule_type,
            action=action,
            threshold=threshold,
            enabled=enabled,
        )

        create_rule_request.additional_properties = d
        return create_rule_request

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
