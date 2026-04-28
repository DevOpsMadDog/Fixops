from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.maintenance_issue_response import MaintenanceIssueResponse
    from ..models.maintenance_report_response_stats import MaintenanceReportResponseStats


T = TypeVar("T", bound="MaintenanceReportResponse")


@_attrs_define
class MaintenanceReportResponse:
    """Full maintenance sweep report.

    Attributes:
        checked_at (str):
        cores_checked (list[int]):
        issues (list[MaintenanceIssueResponse]):
        stats (MaintenanceReportResponseStats):
        duration_ms (float):
        org_id (str):
        issue_count (int):
        critical_count (int):
        high_count (int):
    """

    checked_at: str
    cores_checked: list[int]
    issues: list[MaintenanceIssueResponse]
    stats: MaintenanceReportResponseStats
    duration_ms: float
    org_id: str
    issue_count: int
    critical_count: int
    high_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        checked_at = self.checked_at

        cores_checked = self.cores_checked

        issues = []
        for issues_item_data in self.issues:
            issues_item = issues_item_data.to_dict()
            issues.append(issues_item)

        stats = self.stats.to_dict()

        duration_ms = self.duration_ms

        org_id = self.org_id

        issue_count = self.issue_count

        critical_count = self.critical_count

        high_count = self.high_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "checked_at": checked_at,
                "cores_checked": cores_checked,
                "issues": issues,
                "stats": stats,
                "duration_ms": duration_ms,
                "org_id": org_id,
                "issue_count": issue_count,
                "critical_count": critical_count,
                "high_count": high_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.maintenance_issue_response import MaintenanceIssueResponse
        from ..models.maintenance_report_response_stats import MaintenanceReportResponseStats

        d = dict(src_dict)
        checked_at = d.pop("checked_at")

        cores_checked = cast(list[int], d.pop("cores_checked"))

        issues = []
        _issues = d.pop("issues")
        for issues_item_data in _issues:
            issues_item = MaintenanceIssueResponse.from_dict(issues_item_data)

            issues.append(issues_item)

        stats = MaintenanceReportResponseStats.from_dict(d.pop("stats"))

        duration_ms = d.pop("duration_ms")

        org_id = d.pop("org_id")

        issue_count = d.pop("issue_count")

        critical_count = d.pop("critical_count")

        high_count = d.pop("high_count")

        maintenance_report_response = cls(
            checked_at=checked_at,
            cores_checked=cores_checked,
            issues=issues,
            stats=stats,
            duration_ms=duration_ms,
            org_id=org_id,
            issue_count=issue_count,
            critical_count=critical_count,
            high_count=high_count,
        )

        maintenance_report_response.additional_properties = d
        return maintenance_report_response

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
