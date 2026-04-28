from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VEXUploadRequest")


@_attrs_define
class VEXUploadRequest:
    """Upload VEX document to apply analysis decisions in bulk.

    Attributes:
        project_name (str): Target project name
        vex (str): CycloneDX VEX JSON document as string
        project_version (str | Unset):  Default: 'latest'.
    """

    project_name: str
    vex: str
    project_version: str | Unset = "latest"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        project_name = self.project_name

        vex = self.vex

        project_version = self.project_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "project_name": project_name,
                "vex": vex,
            }
        )
        if project_version is not UNSET:
            field_dict["project_version"] = project_version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        project_name = d.pop("project_name")

        vex = d.pop("vex")

        project_version = d.pop("project_version", UNSET)

        vex_upload_request = cls(
            project_name=project_name,
            vex=vex,
            project_version=project_version,
        )

        vex_upload_request.additional_properties = d
        return vex_upload_request

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
