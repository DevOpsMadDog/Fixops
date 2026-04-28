from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.ip_rule_action import IPRuleAction
from ..types import UNSET, Unset

T = TypeVar("T", bound="AddIPRuleRequest")


@_attrs_define
class AddIPRuleRequest:
    """
    Attributes:
        cidr (str): IP address or CIDR block, e.g. '10.0.0.0/8' or '1.2.3.4'
        action (IPRuleAction):
        description (str | Unset): Human-readable description Default: ''.
        created_by (str | Unset): Who created this rule Default: 'api'.
    """

    cidr: str
    action: IPRuleAction
    description: str | Unset = ""
    created_by: str | Unset = "api"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cidr = self.cidr

        action = self.action.value

        description = self.description

        created_by = self.created_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cidr": cidr,
                "action": action,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if created_by is not UNSET:
            field_dict["created_by"] = created_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cidr = d.pop("cidr")

        action = IPRuleAction(d.pop("action"))

        description = d.pop("description", UNSET)

        created_by = d.pop("created_by", UNSET)

        add_ip_rule_request = cls(
            cidr=cidr,
            action=action,
            description=description,
            created_by=created_by,
        )

        add_ip_rule_request.additional_properties = d
        return add_ip_rule_request

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
