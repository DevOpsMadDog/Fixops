from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PackageCreate")


@_attrs_define
class PackageCreate:
    """
    Attributes:
        name (str):
        ecosystem (str | Unset):  Default: 'pypi'.
        version (str | Unset):  Default: ''.
        license_ (str | Unset):  Default: ''.
        is_direct (bool | Unset):  Default: True.
        risk_level (str | Unset):  Default: 'safe'.
    """

    name: str
    ecosystem: str | Unset = "pypi"
    version: str | Unset = ""
    license_: str | Unset = ""
    is_direct: bool | Unset = True
    risk_level: str | Unset = "safe"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        ecosystem = self.ecosystem

        version = self.version

        license_ = self.license_

        is_direct = self.is_direct

        risk_level = self.risk_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if version is not UNSET:
            field_dict["version"] = version
        if license_ is not UNSET:
            field_dict["license"] = license_
        if is_direct is not UNSET:
            field_dict["is_direct"] = is_direct
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        ecosystem = d.pop("ecosystem", UNSET)

        version = d.pop("version", UNSET)

        license_ = d.pop("license", UNSET)

        is_direct = d.pop("is_direct", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        package_create = cls(
            name=name,
            ecosystem=ecosystem,
            version=version,
            license_=license_,
            is_direct=is_direct,
            risk_level=risk_level,
        )

        package_create.additional_properties = d
        return package_create

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
