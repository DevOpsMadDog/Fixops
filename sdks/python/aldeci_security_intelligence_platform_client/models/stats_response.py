from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.stats_response_by_category import StatsResponseByCategory
    from ..models.stats_response_by_severity import StatsResponseBySeverity


T = TypeVar("T", bound="StatsResponse")


@_attrs_define
class StatsResponse:
    """
    Attributes:
        total_scans (int):
        avg_score (float):
        total_findings (int):
        by_severity (StatsResponseBySeverity):
        by_category (StatsResponseByCategory):
    """

    total_scans: int
    avg_score: float
    total_findings: int
    by_severity: StatsResponseBySeverity
    by_category: StatsResponseByCategory
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_scans = self.total_scans

        avg_score = self.avg_score

        total_findings = self.total_findings

        by_severity = self.by_severity.to_dict()

        by_category = self.by_category.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_scans": total_scans,
                "avg_score": avg_score,
                "total_findings": total_findings,
                "by_severity": by_severity,
                "by_category": by_category,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.stats_response_by_category import StatsResponseByCategory
        from ..models.stats_response_by_severity import StatsResponseBySeverity

        d = dict(src_dict)
        total_scans = d.pop("total_scans")

        avg_score = d.pop("avg_score")

        total_findings = d.pop("total_findings")

        by_severity = StatsResponseBySeverity.from_dict(d.pop("by_severity"))

        by_category = StatsResponseByCategory.from_dict(d.pop("by_category"))

        stats_response = cls(
            total_scans=total_scans,
            avg_score=avg_score,
            total_findings=total_findings,
            by_severity=by_severity,
            by_category=by_category,
        )

        stats_response.additional_properties = d
        return stats_response

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
