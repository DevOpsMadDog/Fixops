from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ContextRequirementRequest")


@_attrs_define
class ContextRequirementRequest:
    """
    Attributes:
        rule_key (str):
        tier (str): metadata|targeted|full_file
        max_tokens (int):
    """

    rule_key: str
    tier: str
    max_tokens: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_key = self.rule_key

        tier = self.tier

        max_tokens = self.max_tokens

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_key": rule_key,
                "tier": tier,
                "max_tokens": max_tokens,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_key = d.pop("rule_key")

        tier = d.pop("tier")

        max_tokens = d.pop("max_tokens")

        context_requirement_request = cls(
            rule_key=rule_key,
            tier=tier,
            max_tokens=max_tokens,
        )

        context_requirement_request.additional_properties = d
        return context_requirement_request

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
