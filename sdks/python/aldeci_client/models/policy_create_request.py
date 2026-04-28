from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.policy_rule import PolicyRule


T = TypeVar("T", bound="PolicyCreateRequest")


@_attrs_define
class PolicyCreateRequest:
    """Create a new CI/CD policy.

    Attributes:
        rules (list[PolicyRule]): Policy rules
        org_id (str | Unset): Organisation ID (optional) Default: ''.
    """

    rules: list[PolicyRule]
    org_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rules = []
        for rules_item_data in self.rules:
            rules_item = rules_item_data.to_dict()
            rules.append(rules_item)

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rules": rules,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.policy_rule import PolicyRule

        d = dict(src_dict)
        rules = []
        _rules = d.pop("rules")
        for rules_item_data in _rules:
            rules_item = PolicyRule.from_dict(rules_item_data)

            rules.append(rules_item)

        org_id = d.pop("org_id", UNSET)

        policy_create_request = cls(
            rules=rules,
            org_id=org_id,
        )

        policy_create_request.additional_properties = d
        return policy_create_request

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
