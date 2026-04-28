from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="MgrScanSummaryResponse")


@_attrs_define
class MgrScanSummaryResponse:
    """
    Attributes:
        scan_id (str):
        scan_type (str):
        target_path (str):
        files_scanned (int):
        commits_scanned (int):
        findings_count (int):
        critical_count (int):
        high_count (int):
        medium_count (int):
        low_count (int):
        started_at (str):
        completed_at (None | str):
        errors (list[str]):
    """

    scan_id: str
    scan_type: str
    target_path: str
    files_scanned: int
    commits_scanned: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: str
    completed_at: None | str
    errors: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_id = self.scan_id

        scan_type = self.scan_type

        target_path = self.target_path

        files_scanned = self.files_scanned

        commits_scanned = self.commits_scanned

        findings_count = self.findings_count

        critical_count = self.critical_count

        high_count = self.high_count

        medium_count = self.medium_count

        low_count = self.low_count

        started_at = self.started_at

        completed_at: None | str
        completed_at = self.completed_at

        errors = self.errors

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scan_id": scan_id,
                "scan_type": scan_type,
                "target_path": target_path,
                "files_scanned": files_scanned,
                "commits_scanned": commits_scanned,
                "findings_count": findings_count,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "started_at": started_at,
                "completed_at": completed_at,
                "errors": errors,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scan_id = d.pop("scan_id")

        scan_type = d.pop("scan_type")

        target_path = d.pop("target_path")

        files_scanned = d.pop("files_scanned")

        commits_scanned = d.pop("commits_scanned")

        findings_count = d.pop("findings_count")

        critical_count = d.pop("critical_count")

        high_count = d.pop("high_count")

        medium_count = d.pop("medium_count")

        low_count = d.pop("low_count")

        started_at = d.pop("started_at")

        def _parse_completed_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        completed_at = _parse_completed_at(d.pop("completed_at"))

        errors = cast(list[str], d.pop("errors"))

        mgr_scan_summary_response = cls(
            scan_id=scan_id,
            scan_type=scan_type,
            target_path=target_path,
            files_scanned=files_scanned,
            commits_scanned=commits_scanned,
            findings_count=findings_count,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            started_at=started_at,
            completed_at=completed_at,
            errors=errors,
        )

        mgr_scan_summary_response.additional_properties = d
        return mgr_scan_summary_response

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
