from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SBOMUploadRequest")


@_attrs_define
class SBOMUploadRequest:
    """Upload SBOM via JSON body (alternative to file upload).

    Attributes:
        project_name (str): Target project name in Dependency-Track
        sbom (str): Raw CycloneDX/SPDX JSON or XML as string
        project_version (str | Unset): Project version tag Default: 'latest'.
        auto_create (bool | Unset): Auto-create project if it doesn't exist Default: True.
    """

    project_name: str
    sbom: str
    project_version: str | Unset = "latest"
    auto_create: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        project_name = self.project_name

        sbom = self.sbom

        project_version = self.project_version

        auto_create = self.auto_create

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "project_name": project_name,
                "sbom": sbom,
            }
        )
        if project_version is not UNSET:
            field_dict["project_version"] = project_version
        if auto_create is not UNSET:
            field_dict["auto_create"] = auto_create

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        project_name = d.pop("project_name")

        sbom = d.pop("sbom")

        project_version = d.pop("project_version", UNSET)

        auto_create = d.pop("auto_create", UNSET)

        sbom_upload_request = cls(
            project_name=project_name,
            sbom=sbom,
            project_version=project_version,
            auto_create=auto_create,
        )

        sbom_upload_request.additional_properties = d
        return sbom_upload_request

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
