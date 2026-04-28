from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SBOMComponent")


@_attrs_define
class SBOMComponent:
    """A single component entry from an SBOM.

    Attributes:
        name (str):
        version (str | Unset):  Default: ''.
        license_expression (None | str | Unset):
        declared_licenses (list[str] | Unset):
        package_url (None | str | Unset):
        supplier (None | str | Unset):
        is_direct_dependency (bool | Unset):  Default: True.
    """

    name: str
    version: str | Unset = ""
    license_expression: None | str | Unset = UNSET
    declared_licenses: list[str] | Unset = UNSET
    package_url: None | str | Unset = UNSET
    supplier: None | str | Unset = UNSET
    is_direct_dependency: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        version = self.version

        license_expression: None | str | Unset
        if isinstance(self.license_expression, Unset):
            license_expression = UNSET
        else:
            license_expression = self.license_expression

        declared_licenses: list[str] | Unset = UNSET
        if not isinstance(self.declared_licenses, Unset):
            declared_licenses = self.declared_licenses

        package_url: None | str | Unset
        if isinstance(self.package_url, Unset):
            package_url = UNSET
        else:
            package_url = self.package_url

        supplier: None | str | Unset
        if isinstance(self.supplier, Unset):
            supplier = UNSET
        else:
            supplier = self.supplier

        is_direct_dependency = self.is_direct_dependency

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if license_expression is not UNSET:
            field_dict["license_expression"] = license_expression
        if declared_licenses is not UNSET:
            field_dict["declared_licenses"] = declared_licenses
        if package_url is not UNSET:
            field_dict["package_url"] = package_url
        if supplier is not UNSET:
            field_dict["supplier"] = supplier
        if is_direct_dependency is not UNSET:
            field_dict["is_direct_dependency"] = is_direct_dependency

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        version = d.pop("version", UNSET)

        def _parse_license_expression(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        license_expression = _parse_license_expression(d.pop("license_expression", UNSET))

        declared_licenses = cast(list[str], d.pop("declared_licenses", UNSET))

        def _parse_package_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        package_url = _parse_package_url(d.pop("package_url", UNSET))

        def _parse_supplier(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        supplier = _parse_supplier(d.pop("supplier", UNSET))

        is_direct_dependency = d.pop("is_direct_dependency", UNSET)

        sbom_component = cls(
            name=name,
            version=version,
            license_expression=license_expression,
            declared_licenses=declared_licenses,
            package_url=package_url,
            supplier=supplier,
            is_direct_dependency=is_direct_dependency,
        )

        sbom_component.additional_properties = d
        return sbom_component

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
