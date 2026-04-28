from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateScanResultRequest")


@_attrs_define
class CreateScanResultRequest:
    """
    Attributes:
        scanner_id (str):
        schedule_id (None | str | Unset):
        scan_start (None | str | Unset):
        scan_end (None | str | Unset):
        assets_scanned (int | Unset):  Default: 0.
        total_findings (int | Unset):  Default: 0.
        critical_count (int | Unset):  Default: 0.
        high_count (int | Unset):  Default: 0.
        medium_count (int | Unset):  Default: 0.
        low_count (int | Unset):  Default: 0.
        status (str | Unset):  Default: 'running'.
    """

    scanner_id: str
    schedule_id: None | str | Unset = UNSET
    scan_start: None | str | Unset = UNSET
    scan_end: None | str | Unset = UNSET
    assets_scanned: int | Unset = 0
    total_findings: int | Unset = 0
    critical_count: int | Unset = 0
    high_count: int | Unset = 0
    medium_count: int | Unset = 0
    low_count: int | Unset = 0
    status: str | Unset = "running"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scanner_id = self.scanner_id

        schedule_id: None | str | Unset
        if isinstance(self.schedule_id, Unset):
            schedule_id = UNSET
        else:
            schedule_id = self.schedule_id

        scan_start: None | str | Unset
        if isinstance(self.scan_start, Unset):
            scan_start = UNSET
        else:
            scan_start = self.scan_start

        scan_end: None | str | Unset
        if isinstance(self.scan_end, Unset):
            scan_end = UNSET
        else:
            scan_end = self.scan_end

        assets_scanned = self.assets_scanned

        total_findings = self.total_findings

        critical_count = self.critical_count

        high_count = self.high_count

        medium_count = self.medium_count

        low_count = self.low_count

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scanner_id": scanner_id,
            }
        )
        if schedule_id is not UNSET:
            field_dict["schedule_id"] = schedule_id
        if scan_start is not UNSET:
            field_dict["scan_start"] = scan_start
        if scan_end is not UNSET:
            field_dict["scan_end"] = scan_end
        if assets_scanned is not UNSET:
            field_dict["assets_scanned"] = assets_scanned
        if total_findings is not UNSET:
            field_dict["total_findings"] = total_findings
        if critical_count is not UNSET:
            field_dict["critical_count"] = critical_count
        if high_count is not UNSET:
            field_dict["high_count"] = high_count
        if medium_count is not UNSET:
            field_dict["medium_count"] = medium_count
        if low_count is not UNSET:
            field_dict["low_count"] = low_count
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scanner_id = d.pop("scanner_id")

        def _parse_schedule_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schedule_id = _parse_schedule_id(d.pop("schedule_id", UNSET))

        def _parse_scan_start(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scan_start = _parse_scan_start(d.pop("scan_start", UNSET))

        def _parse_scan_end(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scan_end = _parse_scan_end(d.pop("scan_end", UNSET))

        assets_scanned = d.pop("assets_scanned", UNSET)

        total_findings = d.pop("total_findings", UNSET)

        critical_count = d.pop("critical_count", UNSET)

        high_count = d.pop("high_count", UNSET)

        medium_count = d.pop("medium_count", UNSET)

        low_count = d.pop("low_count", UNSET)

        status = d.pop("status", UNSET)

        create_scan_result_request = cls(
            scanner_id=scanner_id,
            schedule_id=schedule_id,
            scan_start=scan_start,
            scan_end=scan_end,
            assets_scanned=assets_scanned,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            status=status,
        )

        create_scan_result_request.additional_properties = d
        return create_scan_result_request

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
