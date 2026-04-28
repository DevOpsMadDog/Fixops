from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterComponentRequest")


@_attrs_define
class RegisterComponentRequest:
    """
    Attributes:
        org_id (str): Organisation ID
        project_name (str): Project name
        component_name (str): Component name
        component_version (str): Component version
        component_type (str): library|framework|application|container|device|firmware|file|operating-system
        ecosystem (str | Unset): npm|pypi|maven|nuget|cargo|go|gem|composer Default: ''.
        license_ (str | Unset): SPDX license identifier Default: ''.
        purl (str | Unset): Package URL Default: ''.
        cpe (str | Unset): CPE identifier Default: ''.
        supplier (str | Unset): Supplier/vendor name Default: ''.
        hash_sha256 (str | Unset): SHA-256 hash of component Default: ''.
    """

    org_id: str
    project_name: str
    component_name: str
    component_version: str
    component_type: str
    ecosystem: str | Unset = ""
    license_: str | Unset = ""
    purl: str | Unset = ""
    cpe: str | Unset = ""
    supplier: str | Unset = ""
    hash_sha256: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        project_name = self.project_name

        component_name = self.component_name

        component_version = self.component_version

        component_type = self.component_type

        ecosystem = self.ecosystem

        license_ = self.license_

        purl = self.purl

        cpe = self.cpe

        supplier = self.supplier

        hash_sha256 = self.hash_sha256

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "project_name": project_name,
                "component_name": component_name,
                "component_version": component_version,
                "component_type": component_type,
            }
        )
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if license_ is not UNSET:
            field_dict["license"] = license_
        if purl is not UNSET:
            field_dict["purl"] = purl
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if supplier is not UNSET:
            field_dict["supplier"] = supplier
        if hash_sha256 is not UNSET:
            field_dict["hash_sha256"] = hash_sha256

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        project_name = d.pop("project_name")

        component_name = d.pop("component_name")

        component_version = d.pop("component_version")

        component_type = d.pop("component_type")

        ecosystem = d.pop("ecosystem", UNSET)

        license_ = d.pop("license", UNSET)

        purl = d.pop("purl", UNSET)

        cpe = d.pop("cpe", UNSET)

        supplier = d.pop("supplier", UNSET)

        hash_sha256 = d.pop("hash_sha256", UNSET)

        register_component_request = cls(
            org_id=org_id,
            project_name=project_name,
            component_name=component_name,
            component_version=component_version,
            component_type=component_type,
            ecosystem=ecosystem,
            license_=license_,
            purl=purl,
            cpe=cpe,
            supplier=supplier,
            hash_sha256=hash_sha256,
        )

        register_component_request.additional_properties = d
        return register_component_request

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
