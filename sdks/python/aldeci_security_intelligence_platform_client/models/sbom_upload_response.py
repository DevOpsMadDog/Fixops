from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="SBOMUploadResponse")


@_attrs_define
class SBOMUploadResponse:
    """Response after SBOM ingestion.

    Attributes:
        sbom_id (str):
        format_ (str):
        name (str):
        version (str):
        component_count (int):
        sha256 (str):
        attack_signals_detected (int):
        org_id (str):
    """

    sbom_id: str
    format_: str
    name: str
    version: str
    component_count: int
    sha256: str
    attack_signals_detected: int
    org_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sbom_id = self.sbom_id

        format_ = self.format_

        name = self.name

        version = self.version

        component_count = self.component_count

        sha256 = self.sha256

        attack_signals_detected = self.attack_signals_detected

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sbom_id": sbom_id,
                "format": format_,
                "name": name,
                "version": version,
                "component_count": component_count,
                "sha256": sha256,
                "attack_signals_detected": attack_signals_detected,
                "org_id": org_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        sbom_id = d.pop("sbom_id")

        format_ = d.pop("format")

        name = d.pop("name")

        version = d.pop("version")

        component_count = d.pop("component_count")

        sha256 = d.pop("sha256")

        attack_signals_detected = d.pop("attack_signals_detected")

        org_id = d.pop("org_id")

        sbom_upload_response = cls(
            sbom_id=sbom_id,
            format_=format_,
            name=name,
            version=version,
            component_count=component_count,
            sha256=sha256,
            attack_signals_detected=attack_signals_detected,
            org_id=org_id,
        )

        sbom_upload_response.additional_properties = d
        return sbom_upload_response

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
