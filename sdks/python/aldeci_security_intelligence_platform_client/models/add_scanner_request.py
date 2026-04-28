from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddScannerRequest")


@_attrs_define
class AddScannerRequest:
    """
    Attributes:
        name (str):
        scanner_type (str | Unset):  Default: 'nessus'.
        version (str | Unset):  Default: ''.
        license_type (str | Unset):  Default: 'oss'.
        status (str | Unset):  Default: 'active'.
        last_sync (None | str | Unset):
        scan_count (int | Unset):  Default: 0.
    """

    name: str
    scanner_type: str | Unset = "nessus"
    version: str | Unset = ""
    license_type: str | Unset = "oss"
    status: str | Unset = "active"
    last_sync: None | str | Unset = UNSET
    scan_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        scanner_type = self.scanner_type

        version = self.version

        license_type = self.license_type

        status = self.status

        last_sync: None | str | Unset
        if isinstance(self.last_sync, Unset):
            last_sync = UNSET
        else:
            last_sync = self.last_sync

        scan_count = self.scan_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if scanner_type is not UNSET:
            field_dict["scanner_type"] = scanner_type
        if version is not UNSET:
            field_dict["version"] = version
        if license_type is not UNSET:
            field_dict["license_type"] = license_type
        if status is not UNSET:
            field_dict["status"] = status
        if last_sync is not UNSET:
            field_dict["last_sync"] = last_sync
        if scan_count is not UNSET:
            field_dict["scan_count"] = scan_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        scanner_type = d.pop("scanner_type", UNSET)

        version = d.pop("version", UNSET)

        license_type = d.pop("license_type", UNSET)

        status = d.pop("status", UNSET)

        def _parse_last_sync(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_sync = _parse_last_sync(d.pop("last_sync", UNSET))

        scan_count = d.pop("scan_count", UNSET)

        add_scanner_request = cls(
            name=name,
            scanner_type=scanner_type,
            version=version,
            license_type=license_type,
            status=status,
            last_sync=last_sync,
            scan_count=scan_count,
        )

        add_scanner_request.additional_properties = d
        return add_scanner_request

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
