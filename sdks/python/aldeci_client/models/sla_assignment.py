from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.escalation_level import EscalationLevel
from ..models.sla_status_v2 import SLAStatusV2
from ..types import UNSET, Unset

T = TypeVar("T", bound="SLAAssignment")


@_attrs_define
class SLAAssignment:
    """SLA assignment record for a finding.

    Attributes:
        finding_id (str):
        org_id (str):
        severity (str):
        discovered_at (datetime.datetime):
        deadline (datetime.datetime):
        id (str | Unset):
        team_id (None | str | Unset):
        asset_tier (str | Unset):  Default: 'tier3'.
        frameworks (list[str] | Unset):
        business_hours (bool | Unset):  Default: False.
        status (SLAStatusV2 | Unset): SLA lifecycle states with breach severity.
        pct_elapsed (float | Unset):  Default: 0.0.
        escalation_level (EscalationLevel | Unset): Escalation tiers for SLA notifications.
        breached_at (datetime.datetime | None | Unset):
        resolved_at (datetime.datetime | None | Unset):
        created_at (datetime.datetime | Unset):
    """

    finding_id: str
    org_id: str
    severity: str
    discovered_at: datetime.datetime
    deadline: datetime.datetime
    id: str | Unset = UNSET
    team_id: None | str | Unset = UNSET
    asset_tier: str | Unset = "tier3"
    frameworks: list[str] | Unset = UNSET
    business_hours: bool | Unset = False
    status: SLAStatusV2 | Unset = UNSET
    pct_elapsed: float | Unset = 0.0
    escalation_level: EscalationLevel | Unset = UNSET
    breached_at: datetime.datetime | None | Unset = UNSET
    resolved_at: datetime.datetime | None | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        org_id = self.org_id

        severity = self.severity

        discovered_at = self.discovered_at.isoformat()

        deadline = self.deadline.isoformat()

        id = self.id

        team_id: None | str | Unset
        if isinstance(self.team_id, Unset):
            team_id = UNSET
        else:
            team_id = self.team_id

        asset_tier = self.asset_tier

        frameworks: list[str] | Unset = UNSET
        if not isinstance(self.frameworks, Unset):
            frameworks = self.frameworks

        business_hours = self.business_hours

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        pct_elapsed = self.pct_elapsed

        escalation_level: str | Unset = UNSET
        if not isinstance(self.escalation_level, Unset):
            escalation_level = self.escalation_level.value

        breached_at: None | str | Unset
        if isinstance(self.breached_at, Unset):
            breached_at = UNSET
        elif isinstance(self.breached_at, datetime.datetime):
            breached_at = self.breached_at.isoformat()
        else:
            breached_at = self.breached_at

        resolved_at: None | str | Unset
        if isinstance(self.resolved_at, Unset):
            resolved_at = UNSET
        elif isinstance(self.resolved_at, datetime.datetime):
            resolved_at = self.resolved_at.isoformat()
        else:
            resolved_at = self.resolved_at

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "org_id": org_id,
                "severity": severity,
                "discovered_at": discovered_at,
                "deadline": deadline,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if team_id is not UNSET:
            field_dict["team_id"] = team_id
        if asset_tier is not UNSET:
            field_dict["asset_tier"] = asset_tier
        if frameworks is not UNSET:
            field_dict["frameworks"] = frameworks
        if business_hours is not UNSET:
            field_dict["business_hours"] = business_hours
        if status is not UNSET:
            field_dict["status"] = status
        if pct_elapsed is not UNSET:
            field_dict["pct_elapsed"] = pct_elapsed
        if escalation_level is not UNSET:
            field_dict["escalation_level"] = escalation_level
        if breached_at is not UNSET:
            field_dict["breached_at"] = breached_at
        if resolved_at is not UNSET:
            field_dict["resolved_at"] = resolved_at
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        org_id = d.pop("org_id")

        severity = d.pop("severity")

        discovered_at = isoparse(d.pop("discovered_at"))

        deadline = isoparse(d.pop("deadline"))

        id = d.pop("id", UNSET)

        def _parse_team_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        team_id = _parse_team_id(d.pop("team_id", UNSET))

        asset_tier = d.pop("asset_tier", UNSET)

        frameworks = cast(list[str], d.pop("frameworks", UNSET))

        business_hours = d.pop("business_hours", UNSET)

        _status = d.pop("status", UNSET)
        status: SLAStatusV2 | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = SLAStatusV2(_status)

        pct_elapsed = d.pop("pct_elapsed", UNSET)

        _escalation_level = d.pop("escalation_level", UNSET)
        escalation_level: EscalationLevel | Unset
        if isinstance(_escalation_level, Unset):
            escalation_level = UNSET
        else:
            escalation_level = EscalationLevel(_escalation_level)

        def _parse_breached_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                breached_at_type_0 = isoparse(data)

                return breached_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        breached_at = _parse_breached_at(d.pop("breached_at", UNSET))

        def _parse_resolved_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                resolved_at_type_0 = isoparse(data)

                return resolved_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        resolved_at = _parse_resolved_at(d.pop("resolved_at", UNSET))

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        sla_assignment = cls(
            finding_id=finding_id,
            org_id=org_id,
            severity=severity,
            discovered_at=discovered_at,
            deadline=deadline,
            id=id,
            team_id=team_id,
            asset_tier=asset_tier,
            frameworks=frameworks,
            business_hours=business_hours,
            status=status,
            pct_elapsed=pct_elapsed,
            escalation_level=escalation_level,
            breached_at=breached_at,
            resolved_at=resolved_at,
            created_at=created_at,
        )

        sla_assignment.additional_properties = d
        return sla_assignment

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
