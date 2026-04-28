from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ComponentIn")


@_attrs_define
class ComponentIn:
    """
    Attributes:
        supplier_id (str):
        name (str):
        version (str | Unset):  Default: ''.
        component_type (str | Unset):  Default: 'library'.
        license_ (str | Unset):  Default: ''.
        cve_count (int | Unset):  Default: 0.
        is_eol (bool | Unset):  Default: False.
        purl (str | Unset):  Default: ''.
    """

    supplier_id: str
    name: str
    version: str | Unset = ""
    component_type: str | Unset = "library"
    license_: str | Unset = ""
    cve_count: int | Unset = 0
    is_eol: bool | Unset = False
    purl: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        supplier_id = self.supplier_id

        name = self.name

        version = self.version

        component_type = self.component_type

        license_ = self.license_

        cve_count = self.cve_count

        is_eol = self.is_eol

        purl = self.purl

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "supplier_id": supplier_id,
                "name": name,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if component_type is not UNSET:
            field_dict["component_type"] = component_type
        if license_ is not UNSET:
            field_dict["license"] = license_
        if cve_count is not UNSET:
            field_dict["cve_count"] = cve_count
        if is_eol is not UNSET:
            field_dict["is_eol"] = is_eol
        if purl is not UNSET:
            field_dict["purl"] = purl

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        supplier_id = d.pop("supplier_id")

        name = d.pop("name")

        version = d.pop("version", UNSET)

        component_type = d.pop("component_type", UNSET)

        license_ = d.pop("license", UNSET)

        cve_count = d.pop("cve_count", UNSET)

        is_eol = d.pop("is_eol", UNSET)

        purl = d.pop("purl", UNSET)

        component_in = cls(
            supplier_id=supplier_id,
            name=name,
            version=version,
            component_type=component_type,
            license_=license_,
            cve_count=cve_count,
            is_eol=is_eol,
            purl=purl,
        )

        component_in.additional_properties = d
        return component_in

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
