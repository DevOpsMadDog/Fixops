from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.trend_direction import TrendDirection
from ..types import UNSET, Unset

T = TypeVar("T", bound="TeamMetrics")


@_attrs_define
class TeamMetrics:
    """Per-team SLA performance metrics for a reporting period.

    Attributes:
        org_id (str):
        team_id (str):
        period_start (datetime.datetime):
        period_end (datetime.datetime):
        id (str | Unset):
        total_assigned (int | Unset):  Default: 0.
        resolved_within (int | Unset):  Default: 0.
        breached (int | Unset):  Default: 0.
        avg_resolution_hours (float | Unset):  Default: 0.0.
        compliance_rate (float | Unset):  Default: 0.0.
        trend (TrendDirection | Unset): Team performance trend direction.
        computed_at (datetime.datetime | Unset):
    """

    org_id: str
    team_id: str
    period_start: datetime.datetime
    period_end: datetime.datetime
    id: str | Unset = UNSET
    total_assigned: int | Unset = 0
    resolved_within: int | Unset = 0
    breached: int | Unset = 0
    avg_resolution_hours: float | Unset = 0.0
    compliance_rate: float | Unset = 0.0
    trend: TrendDirection | Unset = UNSET
    computed_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        team_id = self.team_id

        period_start = self.period_start.isoformat()

        period_end = self.period_end.isoformat()

        id = self.id

        total_assigned = self.total_assigned

        resolved_within = self.resolved_within

        breached = self.breached

        avg_resolution_hours = self.avg_resolution_hours

        compliance_rate = self.compliance_rate

        trend: str | Unset = UNSET
        if not isinstance(self.trend, Unset):
            trend = self.trend.value

        computed_at: str | Unset = UNSET
        if not isinstance(self.computed_at, Unset):
            computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "team_id": team_id,
                "period_start": period_start,
                "period_end": period_end,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if total_assigned is not UNSET:
            field_dict["total_assigned"] = total_assigned
        if resolved_within is not UNSET:
            field_dict["resolved_within"] = resolved_within
        if breached is not UNSET:
            field_dict["breached"] = breached
        if avg_resolution_hours is not UNSET:
            field_dict["avg_resolution_hours"] = avg_resolution_hours
        if compliance_rate is not UNSET:
            field_dict["compliance_rate"] = compliance_rate
        if trend is not UNSET:
            field_dict["trend"] = trend
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        team_id = d.pop("team_id")

        period_start = isoparse(d.pop("period_start"))

        period_end = isoparse(d.pop("period_end"))

        id = d.pop("id", UNSET)

        total_assigned = d.pop("total_assigned", UNSET)

        resolved_within = d.pop("resolved_within", UNSET)

        breached = d.pop("breached", UNSET)

        avg_resolution_hours = d.pop("avg_resolution_hours", UNSET)

        compliance_rate = d.pop("compliance_rate", UNSET)

        _trend = d.pop("trend", UNSET)
        trend: TrendDirection | Unset
        if isinstance(_trend, Unset):
            trend = UNSET
        else:
            trend = TrendDirection(_trend)

        _computed_at = d.pop("computed_at", UNSET)
        computed_at: datetime.datetime | Unset
        if isinstance(_computed_at, Unset):
            computed_at = UNSET
        else:
            computed_at = isoparse(_computed_at)

        team_metrics = cls(
            org_id=org_id,
            team_id=team_id,
            period_start=period_start,
            period_end=period_end,
            id=id,
            total_assigned=total_assigned,
            resolved_within=resolved_within,
            breached=breached,
            avg_resolution_hours=avg_resolution_hours,
            compliance_rate=compliance_rate,
            trend=trend,
            computed_at=computed_at,
        )

        team_metrics.additional_properties = d
        return team_metrics

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
