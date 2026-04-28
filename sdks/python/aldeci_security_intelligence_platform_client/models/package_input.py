from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PackageInput")


@_attrs_define
class PackageInput:
    """
    Attributes:
        name (str): Package name
        version (str | Unset): Package version Default: 'unknown'.
        package_manager (str | Unset): Package manager (npm, pypi, maven) Default: 'unknown'.
        age_days (int | None | Unset): Days since first publish
        download_count (int | None | Unset): Total downloads
        maintainer_count (int | None | Unset): Number of maintainers
        has_provenance (bool | None | Unset): Has build provenance attestation
        ownership_changed (bool | None | Unset): Recent ownership transfer
        last_update_days (int | None | Unset): Days since last update
    """

    name: str
    version: str | Unset = "unknown"
    package_manager: str | Unset = "unknown"
    age_days: int | None | Unset = UNSET
    download_count: int | None | Unset = UNSET
    maintainer_count: int | None | Unset = UNSET
    has_provenance: bool | None | Unset = UNSET
    ownership_changed: bool | None | Unset = UNSET
    last_update_days: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        version = self.version

        package_manager = self.package_manager

        age_days: int | None | Unset
        if isinstance(self.age_days, Unset):
            age_days = UNSET
        else:
            age_days = self.age_days

        download_count: int | None | Unset
        if isinstance(self.download_count, Unset):
            download_count = UNSET
        else:
            download_count = self.download_count

        maintainer_count: int | None | Unset
        if isinstance(self.maintainer_count, Unset):
            maintainer_count = UNSET
        else:
            maintainer_count = self.maintainer_count

        has_provenance: bool | None | Unset
        if isinstance(self.has_provenance, Unset):
            has_provenance = UNSET
        else:
            has_provenance = self.has_provenance

        ownership_changed: bool | None | Unset
        if isinstance(self.ownership_changed, Unset):
            ownership_changed = UNSET
        else:
            ownership_changed = self.ownership_changed

        last_update_days: int | None | Unset
        if isinstance(self.last_update_days, Unset):
            last_update_days = UNSET
        else:
            last_update_days = self.last_update_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if package_manager is not UNSET:
            field_dict["package_manager"] = package_manager
        if age_days is not UNSET:
            field_dict["age_days"] = age_days
        if download_count is not UNSET:
            field_dict["download_count"] = download_count
        if maintainer_count is not UNSET:
            field_dict["maintainer_count"] = maintainer_count
        if has_provenance is not UNSET:
            field_dict["has_provenance"] = has_provenance
        if ownership_changed is not UNSET:
            field_dict["ownership_changed"] = ownership_changed
        if last_update_days is not UNSET:
            field_dict["last_update_days"] = last_update_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        version = d.pop("version", UNSET)

        package_manager = d.pop("package_manager", UNSET)

        def _parse_age_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        age_days = _parse_age_days(d.pop("age_days", UNSET))

        def _parse_download_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        download_count = _parse_download_count(d.pop("download_count", UNSET))

        def _parse_maintainer_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        maintainer_count = _parse_maintainer_count(d.pop("maintainer_count", UNSET))

        def _parse_has_provenance(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        has_provenance = _parse_has_provenance(d.pop("has_provenance", UNSET))

        def _parse_ownership_changed(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        ownership_changed = _parse_ownership_changed(d.pop("ownership_changed", UNSET))

        def _parse_last_update_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        last_update_days = _parse_last_update_days(d.pop("last_update_days", UNSET))

        package_input = cls(
            name=name,
            version=version,
            package_manager=package_manager,
            age_days=age_days,
            download_count=download_count,
            maintainer_count=maintainer_count,
            has_provenance=has_provenance,
            ownership_changed=ownership_changed,
            last_update_days=last_update_days,
        )

        package_input.additional_properties = d
        return package_input

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
