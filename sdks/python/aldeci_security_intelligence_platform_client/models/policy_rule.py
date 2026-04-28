from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PolicyRule")


@_attrs_define
class PolicyRule:
    """Single rule within a CI/CD policy.

    Attributes:
        name (str): Human-readable rule name
        severity_threshold (str | Unset): Block if any finding >= this severity (critical|high|medium|low) Default:
            'critical'.
        max_critical (int | Unset): Max allowed critical findings before blocking Default: 0.
        max_high (int | Unset): Max allowed high findings before blocking Default: 5.
        categories (list[str] | Unset): Only apply rule to these finding categories (empty = all)
        enabled (bool | Unset): Whether this rule is active Default: True.
    """

    name: str
    severity_threshold: str | Unset = "critical"
    max_critical: int | Unset = 0
    max_high: int | Unset = 5
    categories: list[str] | Unset = UNSET
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        severity_threshold = self.severity_threshold

        max_critical = self.max_critical

        max_high = self.max_high

        categories: list[str] | Unset = UNSET
        if not isinstance(self.categories, Unset):
            categories = self.categories

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if severity_threshold is not UNSET:
            field_dict["severity_threshold"] = severity_threshold
        if max_critical is not UNSET:
            field_dict["max_critical"] = max_critical
        if max_high is not UNSET:
            field_dict["max_high"] = max_high
        if categories is not UNSET:
            field_dict["categories"] = categories
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        severity_threshold = d.pop("severity_threshold", UNSET)

        max_critical = d.pop("max_critical", UNSET)

        max_high = d.pop("max_high", UNSET)

        categories = cast(list[str], d.pop("categories", UNSET))

        enabled = d.pop("enabled", UNSET)

        policy_rule = cls(
            name=name,
            severity_threshold=severity_threshold,
            max_critical=max_critical,
            max_high=max_high,
            categories=categories,
            enabled=enabled,
        )

        policy_rule.additional_properties = d
        return policy_rule

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
