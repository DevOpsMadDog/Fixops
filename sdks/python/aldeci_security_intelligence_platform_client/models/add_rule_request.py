from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddRuleRequest")


@_attrs_define
class AddRuleRequest:
    """
    Attributes:
        pattern (str): Glob pattern (e.g. 'src/core/**')
        owner_email (str):
        priority (int | Unset):  Default: 0.
    """

    pattern: str
    owner_email: str
    priority: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        pattern = self.pattern

        owner_email = self.owner_email

        priority = self.priority

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "pattern": pattern,
                "owner_email": owner_email,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        pattern = d.pop("pattern")

        owner_email = d.pop("owner_email")

        priority = d.pop("priority", UNSET)

        add_rule_request = cls(
            pattern=pattern,
            owner_email=owner_email,
            priority=priority,
        )

        add_rule_request.additional_properties = d
        return add_rule_request

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
