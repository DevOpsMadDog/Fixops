from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateFilterRuleRequest")


@_attrs_define
class CreateFilterRuleRequest:
    """
    Attributes:
        name (str):
        rule_type (str):
        action (str | Unset):  Default: 'quarantine'.
        priority (int | Unset):  Default: 50.
        pattern (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'active'.
    """

    name: str
    rule_type: str
    action: str | Unset = "quarantine"
    priority: int | Unset = 50
    pattern: str | Unset = ""
    description: str | Unset = ""
    status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        rule_type = self.rule_type

        action = self.action

        priority = self.priority

        pattern = self.pattern

        description = self.description

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "rule_type": rule_type,
            }
        )
        if action is not UNSET:
            field_dict["action"] = action
        if priority is not UNSET:
            field_dict["priority"] = priority
        if pattern is not UNSET:
            field_dict["pattern"] = pattern
        if description is not UNSET:
            field_dict["description"] = description
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        rule_type = d.pop("rule_type")

        action = d.pop("action", UNSET)

        priority = d.pop("priority", UNSET)

        pattern = d.pop("pattern", UNSET)

        description = d.pop("description", UNSET)

        status = d.pop("status", UNSET)

        create_filter_rule_request = cls(
            name=name,
            rule_type=rule_type,
            action=action,
            priority=priority,
            pattern=pattern,
            description=description,
            status=status,
        )

        create_filter_rule_request.additional_properties = d
        return create_filter_rule_request

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
