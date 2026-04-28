from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sla_policy_request_severity_deadlines import SLAPolicyRequestSeverityDeadlines


T = TypeVar("T", bound="SLAPolicyRequest")


@_attrs_define
class SLAPolicyRequest:
    """Payload for creating or updating an SLA policy.

    Attributes:
        name (str):
        severity_deadlines (SLAPolicyRequestSeverityDeadlines | Unset):
        escalation_chain (list[str] | Unset):
        grace_period_hours (int | Unset):  Default: 0.
        enabled (bool | Unset):  Default: True.
    """

    name: str
    severity_deadlines: SLAPolicyRequestSeverityDeadlines | Unset = UNSET
    escalation_chain: list[str] | Unset = UNSET
    grace_period_hours: int | Unset = 0
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        severity_deadlines: dict[str, Any] | Unset = UNSET
        if not isinstance(self.severity_deadlines, Unset):
            severity_deadlines = self.severity_deadlines.to_dict()

        escalation_chain: list[str] | Unset = UNSET
        if not isinstance(self.escalation_chain, Unset):
            escalation_chain = self.escalation_chain

        grace_period_hours = self.grace_period_hours

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if severity_deadlines is not UNSET:
            field_dict["severity_deadlines"] = severity_deadlines
        if escalation_chain is not UNSET:
            field_dict["escalation_chain"] = escalation_chain
        if grace_period_hours is not UNSET:
            field_dict["grace_period_hours"] = grace_period_hours
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sla_policy_request_severity_deadlines import SLAPolicyRequestSeverityDeadlines

        d = dict(src_dict)
        name = d.pop("name")

        _severity_deadlines = d.pop("severity_deadlines", UNSET)
        severity_deadlines: SLAPolicyRequestSeverityDeadlines | Unset
        if isinstance(_severity_deadlines, Unset):
            severity_deadlines = UNSET
        else:
            severity_deadlines = SLAPolicyRequestSeverityDeadlines.from_dict(_severity_deadlines)

        escalation_chain = cast(list[str], d.pop("escalation_chain", UNSET))

        grace_period_hours = d.pop("grace_period_hours", UNSET)

        enabled = d.pop("enabled", UNSET)

        sla_policy_request = cls(
            name=name,
            severity_deadlines=severity_deadlines,
            escalation_chain=escalation_chain,
            grace_period_hours=grace_period_hours,
            enabled=enabled,
        )

        sla_policy_request.additional_properties = d
        return sla_policy_request

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
