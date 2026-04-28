from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.detection_stats_risk_distribution import DetectionStatsRiskDistribution
    from ..models.detection_stats_top_indicators import DetectionStatsTopIndicators


T = TypeVar("T", bound="DetectionStats")


@_attrs_define
class DetectionStats:
    """Aggregate statistics for an org's insider-threat programme.

    Attributes:
        org_id (str):
        total_activities (int):
        total_alerts (int):
        reviewed_alerts (int):
        pending_alerts (int):
        risk_distribution (DetectionStatsRiskDistribution):
        top_indicators (DetectionStatsTopIndicators):
    """

    org_id: str
    total_activities: int
    total_alerts: int
    reviewed_alerts: int
    pending_alerts: int
    risk_distribution: DetectionStatsRiskDistribution
    top_indicators: DetectionStatsTopIndicators
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total_activities = self.total_activities

        total_alerts = self.total_alerts

        reviewed_alerts = self.reviewed_alerts

        pending_alerts = self.pending_alerts

        risk_distribution = self.risk_distribution.to_dict()

        top_indicators = self.top_indicators.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total_activities": total_activities,
                "total_alerts": total_alerts,
                "reviewed_alerts": reviewed_alerts,
                "pending_alerts": pending_alerts,
                "risk_distribution": risk_distribution,
                "top_indicators": top_indicators,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.detection_stats_risk_distribution import DetectionStatsRiskDistribution
        from ..models.detection_stats_top_indicators import DetectionStatsTopIndicators

        d = dict(src_dict)
        org_id = d.pop("org_id")

        total_activities = d.pop("total_activities")

        total_alerts = d.pop("total_alerts")

        reviewed_alerts = d.pop("reviewed_alerts")

        pending_alerts = d.pop("pending_alerts")

        risk_distribution = DetectionStatsRiskDistribution.from_dict(d.pop("risk_distribution"))

        top_indicators = DetectionStatsTopIndicators.from_dict(d.pop("top_indicators"))

        detection_stats = cls(
            org_id=org_id,
            total_activities=total_activities,
            total_alerts=total_alerts,
            reviewed_alerts=reviewed_alerts,
            pending_alerts=pending_alerts,
            risk_distribution=risk_distribution,
            top_indicators=top_indicators,
        )

        detection_stats.additional_properties = d
        return detection_stats

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
