from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SLAConfigSet")


@_attrs_define
class SLAConfigSet:
    """
    Attributes:
        severity (str):
        sla_days (int):
        escalation_days (int | Unset):  Default: 7.
        owner_team (str | Unset):  Default: ''.
    """

    severity: str
    sla_days: int
    escalation_days: int | Unset = 7
    owner_team: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        severity = self.severity

        sla_days = self.sla_days

        escalation_days = self.escalation_days

        owner_team = self.owner_team

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "severity": severity,
                "sla_days": sla_days,
            }
        )
        if escalation_days is not UNSET:
            field_dict["escalation_days"] = escalation_days
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        severity = d.pop("severity")

        sla_days = d.pop("sla_days")

        escalation_days = d.pop("escalation_days", UNSET)

        owner_team = d.pop("owner_team", UNSET)

        sla_config_set = cls(
            severity=severity,
            sla_days=sla_days,
            escalation_days=escalation_days,
            owner_team=owner_team,
        )

        sla_config_set.additional_properties = d
        return sla_config_set

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
