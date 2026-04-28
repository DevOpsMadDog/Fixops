from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SBOMGenerateRequest")


@_attrs_define
class SBOMGenerateRequest:
    """Request body for generating a CycloneDX SBOM from a local manifest.

    Attributes:
        manifest_path (str): Filesystem path to requirements.txt or package.json
        project_name (str | Unset): Project name for SBOM metadata Default: 'unknown'.
        project_version (str | Unset): Project version for SBOM metadata Default: '0.0.0'.
    """

    manifest_path: str
    project_name: str | Unset = "unknown"
    project_version: str | Unset = "0.0.0"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        manifest_path = self.manifest_path

        project_name = self.project_name

        project_version = self.project_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "manifest_path": manifest_path,
            }
        )
        if project_name is not UNSET:
            field_dict["project_name"] = project_name
        if project_version is not UNSET:
            field_dict["project_version"] = project_version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        manifest_path = d.pop("manifest_path")

        project_name = d.pop("project_name", UNSET)

        project_version = d.pop("project_version", UNSET)

        sbom_generate_request = cls(
            manifest_path=manifest_path,
            project_name=project_name,
            project_version=project_version,
        )

        sbom_generate_request.additional_properties = d
        return sbom_generate_request

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
