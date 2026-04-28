from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CreateMitigationRuleRequest")


@_attrs_define
class CreateMitigationRuleRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        name (str): Rule name
        rule_type (str): rate_limit | geo_block | ip_block | challenge
        threshold (Any): Rule threshold value
        action (str): Action to take when rule triggers
    """

    org_id: str
    name: str
    rule_type: str
    threshold: Any
    action: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        name = self.name

        rule_type = self.rule_type

        threshold = self.threshold

        action = self.action

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "name": name,
                "rule_type": rule_type,
                "threshold": threshold,
                "action": action,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        name = d.pop("name")

        rule_type = d.pop("rule_type")

        threshold = d.pop("threshold")

        action = d.pop("action")

        create_mitigation_rule_request = cls(
            org_id=org_id,
            name=name,
            rule_type=rule_type,
            threshold=threshold,
            action=action,
        )

        create_mitigation_rule_request.additional_properties = d
        return create_mitigation_rule_request

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
