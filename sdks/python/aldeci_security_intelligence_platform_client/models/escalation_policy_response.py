from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EscalationPolicyResponse")


@_attrs_define
class EscalationPolicyResponse:
    """
    Attributes:
        org_id (str):
        breach_threshold_hours (int):
        auto_action (str):
        severity_bump (bool):
        updated_at (None | str | Unset):
    """

    org_id: str
    breach_threshold_hours: int
    auto_action: str
    severity_bump: bool
    updated_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        breach_threshold_hours = self.breach_threshold_hours

        auto_action = self.auto_action

        severity_bump = self.severity_bump

        updated_at: None | str | Unset
        if isinstance(self.updated_at, Unset):
            updated_at = UNSET
        else:
            updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "breach_threshold_hours": breach_threshold_hours,
                "auto_action": auto_action,
                "severity_bump": severity_bump,
            }
        )
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        breach_threshold_hours = d.pop("breach_threshold_hours")

        auto_action = d.pop("auto_action")

        severity_bump = d.pop("severity_bump")

        def _parse_updated_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        updated_at = _parse_updated_at(d.pop("updated_at", UNSET))

        escalation_policy_response = cls(
            org_id=org_id,
            breach_threshold_hours=breach_threshold_hours,
            auto_action=auto_action,
            severity_bump=severity_bump,
            updated_at=updated_at,
        )

        escalation_policy_response.additional_properties = d
        return escalation_policy_response

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
