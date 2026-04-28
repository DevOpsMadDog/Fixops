from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TestPackageRequest")


@_attrs_define
class TestPackageRequest:
    """Request body for testing a single package.

    Attributes:
        ecosystem (str): Package ecosystem (npm, pip, maven, etc.)
        package (str): Package name
        version (str): Package version
        org_id (str | Unset): Organisation identifier Default: 'default'.
    """

    ecosystem: str
    package: str
    version: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ecosystem = self.ecosystem

        package = self.package

        version = self.version

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ecosystem": ecosystem,
                "package": package,
                "version": version,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ecosystem = d.pop("ecosystem")

        package = d.pop("package")

        version = d.pop("version")

        org_id = d.pop("org_id", UNSET)

        test_package_request = cls(
            ecosystem=ecosystem,
            package=package,
            version=version,
            org_id=org_id,
        )

        test_package_request.additional_properties = d
        return test_package_request

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
