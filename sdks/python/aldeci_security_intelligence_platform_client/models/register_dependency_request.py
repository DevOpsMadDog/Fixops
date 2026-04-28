from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterDependencyRequest")


@_attrs_define
class RegisterDependencyRequest:
    """
    Attributes:
        package_name (str): Package name
        version (str): Package version
        org_id (str | Unset):  Default: 'default'.
        ecosystem (str | Unset): Ecosystem: npm/pypi/maven/nuget/cargo/go/gem/composer/hex Default: 'npm'.
        license_ (str | Unset): SPDX license identifier Default: ''.
        direct (bool | Unset): True=direct dep, False=transitive Default: True.
        depth (int | Unset): Dependency depth (0=direct) Default: 0.
        parent_package (str | Unset): Parent package name if transitive Default: ''.
    """

    package_name: str
    version: str
    org_id: str | Unset = "default"
    ecosystem: str | Unset = "npm"
    license_: str | Unset = ""
    direct: bool | Unset = True
    depth: int | Unset = 0
    parent_package: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_name = self.package_name

        version = self.version

        org_id = self.org_id

        ecosystem = self.ecosystem

        license_ = self.license_

        direct = self.direct

        depth = self.depth

        parent_package = self.parent_package

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_name": package_name,
                "version": version,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if license_ is not UNSET:
            field_dict["license"] = license_
        if direct is not UNSET:
            field_dict["direct"] = direct
        if depth is not UNSET:
            field_dict["depth"] = depth
        if parent_package is not UNSET:
            field_dict["parent_package"] = parent_package

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package_name = d.pop("package_name")

        version = d.pop("version")

        org_id = d.pop("org_id", UNSET)

        ecosystem = d.pop("ecosystem", UNSET)

        license_ = d.pop("license", UNSET)

        direct = d.pop("direct", UNSET)

        depth = d.pop("depth", UNSET)

        parent_package = d.pop("parent_package", UNSET)

        register_dependency_request = cls(
            package_name=package_name,
            version=version,
            org_id=org_id,
            ecosystem=ecosystem,
            license_=license_,
            direct=direct,
            depth=depth,
            parent_package=parent_package,
        )

        register_dependency_request.additional_properties = d
        return register_dependency_request

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
