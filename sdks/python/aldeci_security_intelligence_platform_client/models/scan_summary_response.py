from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.scan_summary_response_severity_breakdown import ScanSummaryResponseSeverityBreakdown


T = TypeVar("T", bound="ScanSummaryResponse")


@_attrs_define
class ScanSummaryResponse:
    """Scan history entry (findings omitted for brevity).

    Attributes:
        scan_id (str):
        org_id (str):
        target (str):
        rules (str):
        started_at (str):
        completed_at (str):
        status (str):
        is_mock (bool):
        findings_count (int):
        severity_breakdown (ScanSummaryResponseSeverityBreakdown):
        error (None | str | Unset):
    """

    scan_id: str
    org_id: str
    target: str
    rules: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    findings_count: int
    severity_breakdown: ScanSummaryResponseSeverityBreakdown
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_id = self.scan_id

        org_id = self.org_id

        target = self.target

        rules = self.rules

        started_at = self.started_at

        completed_at = self.completed_at

        status = self.status

        is_mock = self.is_mock

        findings_count = self.findings_count

        severity_breakdown = self.severity_breakdown.to_dict()

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scan_id": scan_id,
                "org_id": org_id,
                "target": target,
                "rules": rules,
                "started_at": started_at,
                "completed_at": completed_at,
                "status": status,
                "is_mock": is_mock,
                "findings_count": findings_count,
                "severity_breakdown": severity_breakdown,
            }
        )
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.scan_summary_response_severity_breakdown import ScanSummaryResponseSeverityBreakdown

        d = dict(src_dict)
        scan_id = d.pop("scan_id")

        org_id = d.pop("org_id")

        target = d.pop("target")

        rules = d.pop("rules")

        started_at = d.pop("started_at")

        completed_at = d.pop("completed_at")

        status = d.pop("status")

        is_mock = d.pop("is_mock")

        findings_count = d.pop("findings_count")

        severity_breakdown = ScanSummaryResponseSeverityBreakdown.from_dict(d.pop("severity_breakdown"))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        scan_summary_response = cls(
            scan_id=scan_id,
            org_id=org_id,
            target=target,
            rules=rules,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            is_mock=is_mock,
            findings_count=findings_count,
            severity_breakdown=severity_breakdown,
            error=error,
        )

        scan_summary_response.additional_properties = d
        return scan_summary_response

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
