from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RuleToggleResponse")


@_attrs_define
class RuleToggleResponse:
    """
    Attributes:
        rule_id (str):
        enabled (bool):
        found (bool):
    """

    rule_id: str
    enabled: bool
    found: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_id = self.rule_id

        enabled = self.enabled

        found = self.found

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_id": rule_id,
                "enabled": enabled,
                "found": found,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_id = d.pop("rule_id")

        enabled = d.pop("enabled")

        found = d.pop("found")

        rule_toggle_response = cls(
            rule_id=rule_id,
            enabled=enabled,
            found=found,
        )

        rule_toggle_response.additional_properties = d
        return rule_toggle_response

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
