from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ArtifactCreate")


@_attrs_define
class ArtifactCreate:
    """
    Attributes:
        artifact_type (str | Unset):  Default: 'pcap'.
        size_bytes (int | Unset):  Default: 0.
        findings_count (int | Unset):  Default: 0.
        analysis_json (str | Unset):  Default: ''.
    """

    artifact_type: str | Unset = "pcap"
    size_bytes: int | Unset = 0
    findings_count: int | Unset = 0
    analysis_json: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        artifact_type = self.artifact_type

        size_bytes = self.size_bytes

        findings_count = self.findings_count

        analysis_json = self.analysis_json

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if artifact_type is not UNSET:
            field_dict["artifact_type"] = artifact_type
        if size_bytes is not UNSET:
            field_dict["size_bytes"] = size_bytes
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if analysis_json is not UNSET:
            field_dict["analysis_json"] = analysis_json

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        artifact_type = d.pop("artifact_type", UNSET)

        size_bytes = d.pop("size_bytes", UNSET)

        findings_count = d.pop("findings_count", UNSET)

        analysis_json = d.pop("analysis_json", UNSET)

        artifact_create = cls(
            artifact_type=artifact_type,
            size_bytes=size_bytes,
            findings_count=findings_count,
            analysis_json=analysis_json,
        )

        artifact_create.additional_properties = d
        return artifact_create

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
