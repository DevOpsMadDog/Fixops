from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EscalationRule")


@_attrs_define
class EscalationRule:
    """Escalation targets per severity level.

    Attributes:
        severity (str):
        team_lead_email (None | str | Unset):
        director_email (None | str | Unset):
        ciso_email (None | str | Unset):
    """

    severity: str
    team_lead_email: None | str | Unset = UNSET
    director_email: None | str | Unset = UNSET
    ciso_email: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        severity = self.severity

        team_lead_email: None | str | Unset
        if isinstance(self.team_lead_email, Unset):
            team_lead_email = UNSET
        else:
            team_lead_email = self.team_lead_email

        director_email: None | str | Unset
        if isinstance(self.director_email, Unset):
            director_email = UNSET
        else:
            director_email = self.director_email

        ciso_email: None | str | Unset
        if isinstance(self.ciso_email, Unset):
            ciso_email = UNSET
        else:
            ciso_email = self.ciso_email

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "severity": severity,
            }
        )
        if team_lead_email is not UNSET:
            field_dict["team_lead_email"] = team_lead_email
        if director_email is not UNSET:
            field_dict["director_email"] = director_email
        if ciso_email is not UNSET:
            field_dict["ciso_email"] = ciso_email

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        severity = d.pop("severity")

        def _parse_team_lead_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        team_lead_email = _parse_team_lead_email(d.pop("team_lead_email", UNSET))

        def _parse_director_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        director_email = _parse_director_email(d.pop("director_email", UNSET))

        def _parse_ciso_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ciso_email = _parse_ciso_email(d.pop("ciso_email", UNSET))

        escalation_rule = cls(
            severity=severity,
            team_lead_email=team_lead_email,
            director_email=director_email,
            ciso_email=ciso_email,
        )

        escalation_rule.additional_properties = d
        return escalation_rule

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
