from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SneakernetExportRequest")


@_attrs_define
class SneakernetExportRequest:
    """Request body for exporting a sneakernet update package.

    Attributes:
        payload_files (list[str]): Absolute server-side paths of files to include in the package
        package_type (str): Package type: cve_db | sbom | trustgraph_config | signatures | full_system
        version (str): Semantic version string, e.g. 2025.01.1
        encryption_key_hex (str): 64-hex-char AES-256 key for encrypting the package
        classification (str | Unset): Classification level for the package Default: 'UNCLASSIFIED'.
        output_path (None | str | Unset): Override output file path
    """

    payload_files: list[str]
    package_type: str
    version: str
    encryption_key_hex: str
    classification: str | Unset = "UNCLASSIFIED"
    output_path: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload_files = self.payload_files

        package_type = self.package_type

        version = self.version

        encryption_key_hex = self.encryption_key_hex

        classification = self.classification

        output_path: None | str | Unset
        if isinstance(self.output_path, Unset):
            output_path = UNSET
        else:
            output_path = self.output_path

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "payload_files": payload_files,
                "package_type": package_type,
                "version": version,
                "encryption_key_hex": encryption_key_hex,
            }
        )
        if classification is not UNSET:
            field_dict["classification"] = classification
        if output_path is not UNSET:
            field_dict["output_path"] = output_path

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        payload_files = cast(list[str], d.pop("payload_files"))

        package_type = d.pop("package_type")

        version = d.pop("version")

        encryption_key_hex = d.pop("encryption_key_hex")

        classification = d.pop("classification", UNSET)

        def _parse_output_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        output_path = _parse_output_path(d.pop("output_path", UNSET))

        sneakernet_export_request = cls(
            payload_files=payload_files,
            package_type=package_type,
            version=version,
            encryption_key_hex=encryption_key_hex,
            classification=classification,
            output_path=output_path,
        )

        sneakernet_export_request.additional_properties = d
        return sneakernet_export_request

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
