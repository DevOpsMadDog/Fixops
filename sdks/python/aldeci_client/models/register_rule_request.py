from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.register_rule_request_conditions import RegisterRuleRequestConditions


T = TypeVar("T", bound="RegisterRuleRequest")


@_attrs_define
class RegisterRuleRequest:
    """
    Attributes:
        rule_key (str):
        conditions (RegisterRuleRequestConditions | Unset):
        max_active_count (int | Unset):  Default: 100.
        approvers (list[str] | Unset):
        expires_days (int | Unset):  Default: 30.
    """

    rule_key: str
    conditions: RegisterRuleRequestConditions | Unset = UNSET
    max_active_count: int | Unset = 100
    approvers: list[str] | Unset = UNSET
    expires_days: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_key = self.rule_key

        conditions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.conditions, Unset):
            conditions = self.conditions.to_dict()

        max_active_count = self.max_active_count

        approvers: list[str] | Unset = UNSET
        if not isinstance(self.approvers, Unset):
            approvers = self.approvers

        expires_days = self.expires_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_key": rule_key,
            }
        )
        if conditions is not UNSET:
            field_dict["conditions"] = conditions
        if max_active_count is not UNSET:
            field_dict["max_active_count"] = max_active_count
        if approvers is not UNSET:
            field_dict["approvers"] = approvers
        if expires_days is not UNSET:
            field_dict["expires_days"] = expires_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.register_rule_request_conditions import RegisterRuleRequestConditions

        d = dict(src_dict)
        rule_key = d.pop("rule_key")

        _conditions = d.pop("conditions", UNSET)
        conditions: RegisterRuleRequestConditions | Unset
        if isinstance(_conditions, Unset):
            conditions = UNSET
        else:
            conditions = RegisterRuleRequestConditions.from_dict(_conditions)

        max_active_count = d.pop("max_active_count", UNSET)

        approvers = cast(list[str], d.pop("approvers", UNSET))

        expires_days = d.pop("expires_days", UNSET)

        register_rule_request = cls(
            rule_key=rule_key,
            conditions=conditions,
            max_active_count=max_active_count,
            approvers=approvers,
            expires_days=expires_days,
        )

        register_rule_request.additional_properties = d
        return register_rule_request

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
