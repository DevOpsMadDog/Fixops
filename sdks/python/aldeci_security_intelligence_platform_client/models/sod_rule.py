from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SodRule")


@_attrs_define
class SodRule:
    """
    Attributes:
        rule_name (str):
        entitlement_ids (list[str]):
        severity (str | Unset):  Default: 'medium'.
    """

    rule_name: str
    entitlement_ids: list[str]
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_name = self.rule_name

        entitlement_ids = self.entitlement_ids

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_name": rule_name,
                "entitlement_ids": entitlement_ids,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_name = d.pop("rule_name")

        entitlement_ids = cast(list[str], d.pop("entitlement_ids"))

        severity = d.pop("severity", UNSET)

        sod_rule = cls(
            rule_name=rule_name,
            entitlement_ids=entitlement_ids,
            severity=severity,
        )

        sod_rule.additional_properties = d
        return sod_rule

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
