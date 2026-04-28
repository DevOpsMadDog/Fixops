from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="VulnTrend")


@_attrs_define
class VulnTrend:
    """Vulnerability backlog trend data point.

    Attributes:
        org_id (str):
        period_start (datetime.datetime):
        period_end (datetime.datetime):
        new_vulns (int):
        resolved_vulns (int):
        total_open (int):
        sla_breach_rate (float):
        risk_debt_score (float):
        critical_count (int):
        high_count (int):
        medium_count (int):
        low_count (int):
        mean_time_to_remediate_hours (float | None | Unset):
    """

    org_id: str
    period_start: datetime.datetime
    period_end: datetime.datetime
    new_vulns: int
    resolved_vulns: int
    total_open: int
    sla_breach_rate: float
    risk_debt_score: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    mean_time_to_remediate_hours: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        period_start = self.period_start.isoformat()

        period_end = self.period_end.isoformat()

        new_vulns = self.new_vulns

        resolved_vulns = self.resolved_vulns

        total_open = self.total_open

        sla_breach_rate = self.sla_breach_rate

        risk_debt_score = self.risk_debt_score

        critical_count = self.critical_count

        high_count = self.high_count

        medium_count = self.medium_count

        low_count = self.low_count

        mean_time_to_remediate_hours: float | None | Unset
        if isinstance(self.mean_time_to_remediate_hours, Unset):
            mean_time_to_remediate_hours = UNSET
        else:
            mean_time_to_remediate_hours = self.mean_time_to_remediate_hours

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "period_start": period_start,
                "period_end": period_end,
                "new_vulns": new_vulns,
                "resolved_vulns": resolved_vulns,
                "total_open": total_open,
                "sla_breach_rate": sla_breach_rate,
                "risk_debt_score": risk_debt_score,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
            }
        )
        if mean_time_to_remediate_hours is not UNSET:
            field_dict["mean_time_to_remediate_hours"] = mean_time_to_remediate_hours

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        period_start = isoparse(d.pop("period_start"))

        period_end = isoparse(d.pop("period_end"))

        new_vulns = d.pop("new_vulns")

        resolved_vulns = d.pop("resolved_vulns")

        total_open = d.pop("total_open")

        sla_breach_rate = d.pop("sla_breach_rate")

        risk_debt_score = d.pop("risk_debt_score")

        critical_count = d.pop("critical_count")

        high_count = d.pop("high_count")

        medium_count = d.pop("medium_count")

        low_count = d.pop("low_count")

        def _parse_mean_time_to_remediate_hours(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        mean_time_to_remediate_hours = _parse_mean_time_to_remediate_hours(d.pop("mean_time_to_remediate_hours", UNSET))

        vuln_trend = cls(
            org_id=org_id,
            period_start=period_start,
            period_end=period_end,
            new_vulns=new_vulns,
            resolved_vulns=resolved_vulns,
            total_open=total_open,
            sla_breach_rate=sla_breach_rate,
            risk_debt_score=risk_debt_score,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            mean_time_to_remediate_hours=mean_time_to_remediate_hours,
        )

        vuln_trend.additional_properties = d
        return vuln_trend

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
