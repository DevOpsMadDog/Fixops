from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="PostureDiff")


@_attrs_define
class PostureDiff:
    """Comparison between two PostureSnapshots.

    Attributes:
        snapshot_id_1 (str):
        snapshot_id_2 (str):
        timestamp_1 (str):
        timestamp_2 (str):
        org_id (str):
        score_delta (float): score2 - score1 (positive = improved)
        critical_delta (int): critical_findings2 - critical_findings1
        high_delta (int): high_findings2 - high_findings1
        sla_delta (float): sla_compliance_rate2 - sla_compliance_rate1
        coverage_delta (float): trustgraph_coverage2 - trustgraph_coverage1
        remediation_delta (float): remediation_rate2 - remediation_rate1
        trend (str): 'improving', 'stable', or 'degrading'
        summary (str): Human-readable summary of changes
    """

    snapshot_id_1: str
    snapshot_id_2: str
    timestamp_1: str
    timestamp_2: str
    org_id: str
    score_delta: float
    critical_delta: int
    high_delta: int
    sla_delta: float
    coverage_delta: float
    remediation_delta: float
    trend: str
    summary: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        snapshot_id_1 = self.snapshot_id_1

        snapshot_id_2 = self.snapshot_id_2

        timestamp_1 = self.timestamp_1

        timestamp_2 = self.timestamp_2

        org_id = self.org_id

        score_delta = self.score_delta

        critical_delta = self.critical_delta

        high_delta = self.high_delta

        sla_delta = self.sla_delta

        coverage_delta = self.coverage_delta

        remediation_delta = self.remediation_delta

        trend = self.trend

        summary = self.summary

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "snapshot_id_1": snapshot_id_1,
                "snapshot_id_2": snapshot_id_2,
                "timestamp_1": timestamp_1,
                "timestamp_2": timestamp_2,
                "org_id": org_id,
                "score_delta": score_delta,
                "critical_delta": critical_delta,
                "high_delta": high_delta,
                "sla_delta": sla_delta,
                "coverage_delta": coverage_delta,
                "remediation_delta": remediation_delta,
                "trend": trend,
                "summary": summary,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        snapshot_id_1 = d.pop("snapshot_id_1")

        snapshot_id_2 = d.pop("snapshot_id_2")

        timestamp_1 = d.pop("timestamp_1")

        timestamp_2 = d.pop("timestamp_2")

        org_id = d.pop("org_id")

        score_delta = d.pop("score_delta")

        critical_delta = d.pop("critical_delta")

        high_delta = d.pop("high_delta")

        sla_delta = d.pop("sla_delta")

        coverage_delta = d.pop("coverage_delta")

        remediation_delta = d.pop("remediation_delta")

        trend = d.pop("trend")

        summary = d.pop("summary")

        posture_diff = cls(
            snapshot_id_1=snapshot_id_1,
            snapshot_id_2=snapshot_id_2,
            timestamp_1=timestamp_1,
            timestamp_2=timestamp_2,
            org_id=org_id,
            score_delta=score_delta,
            critical_delta=critical_delta,
            high_delta=high_delta,
            sla_delta=sla_delta,
            coverage_delta=coverage_delta,
            remediation_delta=remediation_delta,
            trend=trend,
            summary=summary,
        )

        posture_diff.additional_properties = d
        return posture_diff

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
