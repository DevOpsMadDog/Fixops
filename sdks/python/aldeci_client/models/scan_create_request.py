from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanCreateRequest")


@_attrs_define
class ScanCreateRequest:
    """
    Attributes:
        app_id (str):
        tool (str):
        scan_type (str | Unset):  Default: 'sast'.
        status (str | Unset):  Default: 'pending'.
        findings_count (int | Unset):  Default: 0.
        critical_count (int | Unset):  Default: 0.
        high_count (int | Unset):  Default: 0.
        medium_count (int | Unset):  Default: 0.
        low_count (int | Unset):  Default: 0.
        started_at (None | str | Unset):
        completed_at (None | str | Unset):
    """

    app_id: str
    tool: str
    scan_type: str | Unset = "sast"
    status: str | Unset = "pending"
    findings_count: int | Unset = 0
    critical_count: int | Unset = 0
    high_count: int | Unset = 0
    medium_count: int | Unset = 0
    low_count: int | Unset = 0
    started_at: None | str | Unset = UNSET
    completed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_id = self.app_id

        tool = self.tool

        scan_type = self.scan_type

        status = self.status

        findings_count = self.findings_count

        critical_count = self.critical_count

        high_count = self.high_count

        medium_count = self.medium_count

        low_count = self.low_count

        started_at: None | str | Unset
        if isinstance(self.started_at, Unset):
            started_at = UNSET
        else:
            started_at = self.started_at

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_id": app_id,
                "tool": tool,
            }
        )
        if scan_type is not UNSET:
            field_dict["scan_type"] = scan_type
        if status is not UNSET:
            field_dict["status"] = status
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if critical_count is not UNSET:
            field_dict["critical_count"] = critical_count
        if high_count is not UNSET:
            field_dict["high_count"] = high_count
        if medium_count is not UNSET:
            field_dict["medium_count"] = medium_count
        if low_count is not UNSET:
            field_dict["low_count"] = low_count
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_id = d.pop("app_id")

        tool = d.pop("tool")

        scan_type = d.pop("scan_type", UNSET)

        status = d.pop("status", UNSET)

        findings_count = d.pop("findings_count", UNSET)

        critical_count = d.pop("critical_count", UNSET)

        high_count = d.pop("high_count", UNSET)

        medium_count = d.pop("medium_count", UNSET)

        low_count = d.pop("low_count", UNSET)

        def _parse_started_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        started_at = _parse_started_at(d.pop("started_at", UNSET))

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        scan_create_request = cls(
            app_id=app_id,
            tool=tool,
            scan_type=scan_type,
            status=status,
            findings_count=findings_count,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            started_at=started_at,
            completed_at=completed_at,
        )

        scan_create_request.additional_properties = d
        return scan_create_request

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
