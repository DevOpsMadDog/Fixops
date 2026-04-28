from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="HuntRuleRequest")


@_attrs_define
class HuntRuleRequest:
    """
    Attributes:
        name (str):
        query (str):
        description (str | Unset):  Default: ''.
        severity (str | Unset): low/medium/high/critical Default: 'medium'.
        auto_alert (bool | Unset):  Default: False.
    """

    name: str
    query: str
    description: str | Unset = ""
    severity: str | Unset = "medium"
    auto_alert: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        query = self.query

        description = self.description

        severity = self.severity

        auto_alert = self.auto_alert

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "query": query,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if auto_alert is not UNSET:
            field_dict["auto_alert"] = auto_alert

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        query = d.pop("query")

        description = d.pop("description", UNSET)

        severity = d.pop("severity", UNSET)

        auto_alert = d.pop("auto_alert", UNSET)

        hunt_rule_request = cls(
            name=name,
            query=query,
            description=description,
            severity=severity,
            auto_alert=auto_alert,
        )

        hunt_rule_request.additional_properties = d
        return hunt_rule_request

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
