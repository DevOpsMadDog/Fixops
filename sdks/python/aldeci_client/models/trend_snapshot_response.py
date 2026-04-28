from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

T = TypeVar("T", bound="TrendSnapshotResponse")


@_attrs_define
class TrendSnapshotResponse:
    """Single weekly risk posture snapshot.

    Attributes:
        week_start (datetime.datetime):
        total_risk_score (float):
        critical_vulns (int):
        high_vulns (int):
        medium_vulns (int):
        low_vulns (int):
        compliance_pct (float):
        mttr_days (float):
        new_findings (int):
        resolved_findings (int):
        new_vs_resolved_ratio (float):
    """

    week_start: datetime.datetime
    total_risk_score: float
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int
    compliance_pct: float
    mttr_days: float
    new_findings: int
    resolved_findings: int
    new_vs_resolved_ratio: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        week_start = self.week_start.isoformat()

        total_risk_score = self.total_risk_score

        critical_vulns = self.critical_vulns

        high_vulns = self.high_vulns

        medium_vulns = self.medium_vulns

        low_vulns = self.low_vulns

        compliance_pct = self.compliance_pct

        mttr_days = self.mttr_days

        new_findings = self.new_findings

        resolved_findings = self.resolved_findings

        new_vs_resolved_ratio = self.new_vs_resolved_ratio

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "week_start": week_start,
                "total_risk_score": total_risk_score,
                "critical_vulns": critical_vulns,
                "high_vulns": high_vulns,
                "medium_vulns": medium_vulns,
                "low_vulns": low_vulns,
                "compliance_pct": compliance_pct,
                "mttr_days": mttr_days,
                "new_findings": new_findings,
                "resolved_findings": resolved_findings,
                "new_vs_resolved_ratio": new_vs_resolved_ratio,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        week_start = isoparse(d.pop("week_start"))

        total_risk_score = d.pop("total_risk_score")

        critical_vulns = d.pop("critical_vulns")

        high_vulns = d.pop("high_vulns")

        medium_vulns = d.pop("medium_vulns")

        low_vulns = d.pop("low_vulns")

        compliance_pct = d.pop("compliance_pct")

        mttr_days = d.pop("mttr_days")

        new_findings = d.pop("new_findings")

        resolved_findings = d.pop("resolved_findings")

        new_vs_resolved_ratio = d.pop("new_vs_resolved_ratio")

        trend_snapshot_response = cls(
            week_start=week_start,
            total_risk_score=total_risk_score,
            critical_vulns=critical_vulns,
            high_vulns=high_vulns,
            medium_vulns=medium_vulns,
            low_vulns=low_vulns,
            compliance_pct=compliance_pct,
            mttr_days=mttr_days,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            new_vs_resolved_ratio=new_vs_resolved_ratio,
        )

        trend_snapshot_response.additional_properties = d
        return trend_snapshot_response

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
