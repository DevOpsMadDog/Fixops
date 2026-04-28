from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cve_ref import CVERef


T = TypeVar("T", bound="SBOMPackageEntry")


@_attrs_define
class SBOMPackageEntry:
    """
    Attributes:
        name (str):
        ecosystem (str | Unset):  Default: 'pypi'.
        version (str | Unset):  Default: ''.
        is_direct (bool | Unset):  Default: True.
        license_ok (bool | Unset):  Default: True.
        cve_ids (list[CVERef] | Unset):
    """

    name: str
    ecosystem: str | Unset = "pypi"
    version: str | Unset = ""
    is_direct: bool | Unset = True
    license_ok: bool | Unset = True
    cve_ids: list[CVERef] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        ecosystem = self.ecosystem

        version = self.version

        is_direct = self.is_direct

        license_ok = self.license_ok

        cve_ids: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = []
            for cve_ids_item_data in self.cve_ids:
                cve_ids_item = cve_ids_item_data.to_dict()
                cve_ids.append(cve_ids_item)

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
        if is_direct is not UNSET:
            field_dict["is_direct"] = is_direct
        if license_ok is not UNSET:
            field_dict["license_ok"] = license_ok
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cve_ref import CVERef

        d = dict(src_dict)
        name = d.pop("name")

        ecosystem = d.pop("ecosystem", UNSET)

        version = d.pop("version", UNSET)

        is_direct = d.pop("is_direct", UNSET)

        license_ok = d.pop("license_ok", UNSET)

        _cve_ids = d.pop("cve_ids", UNSET)
        cve_ids: list[CVERef] | Unset = UNSET
        if _cve_ids is not UNSET:
            cve_ids = []
            for cve_ids_item_data in _cve_ids:
                cve_ids_item = CVERef.from_dict(cve_ids_item_data)

                cve_ids.append(cve_ids_item)

        sbom_package_entry = cls(
            name=name,
            ecosystem=ecosystem,
            version=version,
            is_direct=is_direct,
            license_ok=license_ok,
            cve_ids=cve_ids,
        )

        sbom_package_entry.additional_properties = d
        return sbom_package_entry

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
