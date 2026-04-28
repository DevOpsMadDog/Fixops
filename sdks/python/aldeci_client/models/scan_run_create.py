from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanRunCreate")


@_attrs_define
class ScanRunCreate:
    """
    Attributes:
        scan_type (str | Unset):  Default: 'sast'.
        tool (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'running'.
        started_at (None | str | Unset):
        completed_at (None | str | Unset):
        findings_count (int | Unset):  Default: 0.
        critical_count (int | Unset):  Default: 0.
        high_count (int | Unset):  Default: 0.
    """

    scan_type: str | Unset = "sast"
    tool: str | Unset = ""
    status: str | Unset = "running"
    started_at: None | str | Unset = UNSET
    completed_at: None | str | Unset = UNSET
    findings_count: int | Unset = 0
    critical_count: int | Unset = 0
    high_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_type = self.scan_type

        tool = self.tool

        status = self.status

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

        findings_count = self.findings_count

        critical_count = self.critical_count

        high_count = self.high_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if scan_type is not UNSET:
            field_dict["scan_type"] = scan_type
        if tool is not UNSET:
            field_dict["tool"] = tool
        if status is not UNSET:
            field_dict["status"] = status
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if critical_count is not UNSET:
            field_dict["critical_count"] = critical_count
        if high_count is not UNSET:
            field_dict["high_count"] = high_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scan_type = d.pop("scan_type", UNSET)

        tool = d.pop("tool", UNSET)

        status = d.pop("status", UNSET)

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

        findings_count = d.pop("findings_count", UNSET)

        critical_count = d.pop("critical_count", UNSET)

        high_count = d.pop("high_count", UNSET)

        scan_run_create = cls(
            scan_type=scan_type,
            tool=tool,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            findings_count=findings_count,
            critical_count=critical_count,
            high_count=high_count,
        )

        scan_run_create.additional_properties = d
        return scan_run_create

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
