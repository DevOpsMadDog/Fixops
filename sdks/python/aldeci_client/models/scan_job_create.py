from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanJobCreate")


@_attrs_define
class ScanJobCreate:
    """
    Attributes:
        started_at (str | Unset):  Default: ''.
        records_scanned (int | Unset):  Default: 0.
        findings_count (int | Unset):  Default: 0.
        scanner_version (str | Unset):  Default: ''.
    """

    started_at: str | Unset = ""
    records_scanned: int | Unset = 0
    findings_count: int | Unset = 0
    scanner_version: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        started_at = self.started_at

        records_scanned = self.records_scanned

        findings_count = self.findings_count

        scanner_version = self.scanner_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if records_scanned is not UNSET:
            field_dict["records_scanned"] = records_scanned
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if scanner_version is not UNSET:
            field_dict["scanner_version"] = scanner_version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        started_at = d.pop("started_at", UNSET)

        records_scanned = d.pop("records_scanned", UNSET)

        findings_count = d.pop("findings_count", UNSET)

        scanner_version = d.pop("scanner_version", UNSET)

        scan_job_create = cls(
            started_at=started_at,
            records_scanned=records_scanned,
            findings_count=findings_count,
            scanner_version=scanner_version,
        )

        scan_job_create.additional_properties = d
        return scan_job_create

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
