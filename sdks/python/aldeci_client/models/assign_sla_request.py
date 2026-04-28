from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssignSLARequest")


@_attrs_define
class AssignSLARequest:
    """Request to assign an SLA to a finding.

    Attributes:
        finding_id (str):
        severity (str): critical | high | medium | low
        discovered_at (datetime.datetime | None | Unset): Discovery timestamp (UTC); defaults to now
        team_id (None | str | Unset):
        asset_tier (str | Unset): tier1–tier5 Default: 'tier3'.
        frameworks (list[str] | Unset): Active compliance frameworks (e.g. pci-dss, hipaa)
    """

    finding_id: str
    severity: str
    discovered_at: datetime.datetime | None | Unset = UNSET
    team_id: None | str | Unset = UNSET
    asset_tier: str | Unset = "tier3"
    frameworks: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        severity = self.severity

        discovered_at: None | str | Unset
        if isinstance(self.discovered_at, Unset):
            discovered_at = UNSET
        elif isinstance(self.discovered_at, datetime.datetime):
            discovered_at = self.discovered_at.isoformat()
        else:
            discovered_at = self.discovered_at

        team_id: None | str | Unset
        if isinstance(self.team_id, Unset):
            team_id = UNSET
        else:
            team_id = self.team_id

        asset_tier = self.asset_tier

        frameworks: list[str] | Unset = UNSET
        if not isinstance(self.frameworks, Unset):
            frameworks = self.frameworks

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "severity": severity,
            }
        )
        if discovered_at is not UNSET:
            field_dict["discovered_at"] = discovered_at
        if team_id is not UNSET:
            field_dict["team_id"] = team_id
        if asset_tier is not UNSET:
            field_dict["asset_tier"] = asset_tier
        if frameworks is not UNSET:
            field_dict["frameworks"] = frameworks

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        severity = d.pop("severity")

        def _parse_discovered_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                discovered_at_type_0 = isoparse(data)

                return discovered_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        discovered_at = _parse_discovered_at(d.pop("discovered_at", UNSET))

        def _parse_team_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        team_id = _parse_team_id(d.pop("team_id", UNSET))

        asset_tier = d.pop("asset_tier", UNSET)

        frameworks = cast(list[str], d.pop("frameworks", UNSET))

        assign_sla_request = cls(
            finding_id=finding_id,
            severity=severity,
            discovered_at=discovered_at,
            team_id=team_id,
            asset_tier=asset_tier,
            frameworks=frameworks,
        )

        assign_sla_request.additional_properties = d
        return assign_sla_request

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
