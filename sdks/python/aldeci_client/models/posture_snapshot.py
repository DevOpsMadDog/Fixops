from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.posture_snapshot_components import PostureSnapshotComponents


T = TypeVar("T", bound="PostureSnapshot")


@_attrs_define
class PostureSnapshot:
    """Lightweight posture record at a point in time.

    Attributes:
        org_id (str): Organisation identifier
        overall_score (float): Posture score 0-100
        snapshot_id (str | Unset): Unique snapshot identifier
        timestamp (str | Unset): ISO-8601 UTC timestamp
        critical_findings (int | Unset): Open critical severity findings Default: 0.
        high_findings (int | Unset): Open high severity findings Default: 0.
        medium_findings (int | Unset): Open medium severity findings Default: 0.
        low_findings (int | Unset): Open low severity findings Default: 0.
        sla_compliance_rate (float | Unset): Percentage of findings resolved within SLA Default: 0.0.
        trustgraph_coverage (float | Unset): Percentage of assets indexed in TrustGraph Default: 0.0.
        remediation_rate (float | Unset): Findings remediated in last 30 days (%) Default: 0.0.
        trend (str | Unset): Trend vs previous snapshot: 'improving', 'stable', or 'degrading' Default: 'stable'.
        components (PostureSnapshotComponents | Unset): Raw component scores from PostureScorer (optional)
    """

    org_id: str
    overall_score: float
    snapshot_id: str | Unset = UNSET
    timestamp: str | Unset = UNSET
    critical_findings: int | Unset = 0
    high_findings: int | Unset = 0
    medium_findings: int | Unset = 0
    low_findings: int | Unset = 0
    sla_compliance_rate: float | Unset = 0.0
    trustgraph_coverage: float | Unset = 0.0
    remediation_rate: float | Unset = 0.0
    trend: str | Unset = "stable"
    components: PostureSnapshotComponents | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        overall_score = self.overall_score

        snapshot_id = self.snapshot_id

        timestamp = self.timestamp

        critical_findings = self.critical_findings

        high_findings = self.high_findings

        medium_findings = self.medium_findings

        low_findings = self.low_findings

        sla_compliance_rate = self.sla_compliance_rate

        trustgraph_coverage = self.trustgraph_coverage

        remediation_rate = self.remediation_rate

        trend = self.trend

        components: dict[str, Any] | Unset = UNSET
        if not isinstance(self.components, Unset):
            components = self.components.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "overall_score": overall_score,
            }
        )
        if snapshot_id is not UNSET:
            field_dict["snapshot_id"] = snapshot_id
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if critical_findings is not UNSET:
            field_dict["critical_findings"] = critical_findings
        if high_findings is not UNSET:
            field_dict["high_findings"] = high_findings
        if medium_findings is not UNSET:
            field_dict["medium_findings"] = medium_findings
        if low_findings is not UNSET:
            field_dict["low_findings"] = low_findings
        if sla_compliance_rate is not UNSET:
            field_dict["sla_compliance_rate"] = sla_compliance_rate
        if trustgraph_coverage is not UNSET:
            field_dict["trustgraph_coverage"] = trustgraph_coverage
        if remediation_rate is not UNSET:
            field_dict["remediation_rate"] = remediation_rate
        if trend is not UNSET:
            field_dict["trend"] = trend
        if components is not UNSET:
            field_dict["components"] = components

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.posture_snapshot_components import PostureSnapshotComponents

        d = dict(src_dict)
        org_id = d.pop("org_id")

        overall_score = d.pop("overall_score")

        snapshot_id = d.pop("snapshot_id", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        critical_findings = d.pop("critical_findings", UNSET)

        high_findings = d.pop("high_findings", UNSET)

        medium_findings = d.pop("medium_findings", UNSET)

        low_findings = d.pop("low_findings", UNSET)

        sla_compliance_rate = d.pop("sla_compliance_rate", UNSET)

        trustgraph_coverage = d.pop("trustgraph_coverage", UNSET)

        remediation_rate = d.pop("remediation_rate", UNSET)

        trend = d.pop("trend", UNSET)

        _components = d.pop("components", UNSET)
        components: PostureSnapshotComponents | Unset
        if isinstance(_components, Unset):
            components = UNSET
        else:
            components = PostureSnapshotComponents.from_dict(_components)

        posture_snapshot = cls(
            org_id=org_id,
            overall_score=overall_score,
            snapshot_id=snapshot_id,
            timestamp=timestamp,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            sla_compliance_rate=sla_compliance_rate,
            trustgraph_coverage=trustgraph_coverage,
            remediation_rate=remediation_rate,
            trend=trend,
            components=components,
        )

        posture_snapshot.additional_properties = d
        return posture_snapshot

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
