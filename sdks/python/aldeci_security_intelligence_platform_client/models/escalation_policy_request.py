from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EscalationPolicyRequest")


@_attrs_define
class EscalationPolicyRequest:
    """
    Attributes:
        breach_threshold_hours (int | Unset): Hours past SLA deadline before auto-escalation fires Default: 24.
        auto_action (str | Unset): Default escalation action Default: 'notify'.
        severity_bump (bool | Unset): Whether to bump severity on escalation Default: False.
    """

    breach_threshold_hours: int | Unset = 24
    auto_action: str | Unset = "notify"
    severity_bump: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        breach_threshold_hours = self.breach_threshold_hours

        auto_action = self.auto_action

        severity_bump = self.severity_bump

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if breach_threshold_hours is not UNSET:
            field_dict["breach_threshold_hours"] = breach_threshold_hours
        if auto_action is not UNSET:
            field_dict["auto_action"] = auto_action
        if severity_bump is not UNSET:
            field_dict["severity_bump"] = severity_bump

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        breach_threshold_hours = d.pop("breach_threshold_hours", UNSET)

        auto_action = d.pop("auto_action", UNSET)

        severity_bump = d.pop("severity_bump", UNSET)

        escalation_policy_request = cls(
            breach_threshold_hours=breach_threshold_hours,
            auto_action=auto_action,
            severity_bump=severity_bump,
        )

        escalation_policy_request.additional_properties = d
        return escalation_policy_request

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
