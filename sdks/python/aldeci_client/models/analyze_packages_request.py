from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.package_input import PackageInput


T = TypeVar("T", bound="AnalyzePackagesRequest")


@_attrs_define
class AnalyzePackagesRequest:
    """
    Attributes:
        packages (list[PackageInput]):
        typosquat_threshold (int | Unset):  Default: 2.
        min_age_days (int | Unset):  Default: 30.
        min_downloads (int | Unset):  Default: 100.
    """

    packages: list[PackageInput]
    typosquat_threshold: int | Unset = 2
    min_age_days: int | Unset = 30
    min_downloads: int | Unset = 100
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        packages = []
        for packages_item_data in self.packages:
            packages_item = packages_item_data.to_dict()
            packages.append(packages_item)

        typosquat_threshold = self.typosquat_threshold

        min_age_days = self.min_age_days

        min_downloads = self.min_downloads

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "packages": packages,
            }
        )
        if typosquat_threshold is not UNSET:
            field_dict["typosquat_threshold"] = typosquat_threshold
        if min_age_days is not UNSET:
            field_dict["min_age_days"] = min_age_days
        if min_downloads is not UNSET:
            field_dict["min_downloads"] = min_downloads

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.package_input import PackageInput

        d = dict(src_dict)
        packages = []
        _packages = d.pop("packages")
        for packages_item_data in _packages:
            packages_item = PackageInput.from_dict(packages_item_data)

            packages.append(packages_item)

        typosquat_threshold = d.pop("typosquat_threshold", UNSET)

        min_age_days = d.pop("min_age_days", UNSET)

        min_downloads = d.pop("min_downloads", UNSET)

        analyze_packages_request = cls(
            packages=packages,
            typosquat_threshold=typosquat_threshold,
            min_age_days=min_age_days,
            min_downloads=min_downloads,
        )

        analyze_packages_request.additional_properties = d
        return analyze_packages_request

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
