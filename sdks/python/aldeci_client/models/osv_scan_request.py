from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.osv_scan_request_packages_item import OSVScanRequestPackagesItem


T = TypeVar("T", bound="OSVScanRequest")


@_attrs_define
class OSVScanRequest:
    """Request body for an OSV vulnerability scan of listed packages.

    Attributes:
        packages (list[OSVScanRequestPackagesItem]): List of {name, version, ecosystem} dicts. ecosystem:
            PyPI|npm|Go|Maven
    """

    packages: list[OSVScanRequestPackagesItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        packages = []
        for packages_item_data in self.packages:
            packages_item = packages_item_data.to_dict()
            packages.append(packages_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "packages": packages,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.osv_scan_request_packages_item import OSVScanRequestPackagesItem

        d = dict(src_dict)
        packages = []
        _packages = d.pop("packages")
        for packages_item_data in _packages:
            packages_item = OSVScanRequestPackagesItem.from_dict(packages_item_data)

            packages.append(packages_item)

        osv_scan_request = cls(
            packages=packages,
        )

        osv_scan_request.additional_properties = d
        return osv_scan_request

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
