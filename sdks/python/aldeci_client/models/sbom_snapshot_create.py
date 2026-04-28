from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sbom_package_entry import SBOMPackageEntry


T = TypeVar("T", bound="SBOMSnapshotCreate")


@_attrs_define
class SBOMSnapshotCreate:
    """
    Attributes:
        project_name (str):
        packages (list[SBOMPackageEntry] | Unset):
    """

    project_name: str
    packages: list[SBOMPackageEntry] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        project_name = self.project_name

        packages: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.packages, Unset):
            packages = []
            for packages_item_data in self.packages:
                packages_item = packages_item_data.to_dict()
                packages.append(packages_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "project_name": project_name,
            }
        )
        if packages is not UNSET:
            field_dict["packages"] = packages

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sbom_package_entry import SBOMPackageEntry

        d = dict(src_dict)
        project_name = d.pop("project_name")

        _packages = d.pop("packages", UNSET)
        packages: list[SBOMPackageEntry] | Unset = UNSET
        if _packages is not UNSET:
            packages = []
            for packages_item_data in _packages:
                packages_item = SBOMPackageEntry.from_dict(packages_item_data)

                packages.append(packages_item)

        sbom_snapshot_create = cls(
            project_name=project_name,
            packages=packages,
        )

        sbom_snapshot_create.additional_properties = d
        return sbom_snapshot_create

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
