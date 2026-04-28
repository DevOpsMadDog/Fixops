from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceSubmit")


@_attrs_define
class EvidenceSubmit:
    """
    Attributes:
        evidence_type (str | Unset): document | screenshot | log | config | attestation Default: 'document'.
        filename (str | Unset): Filename of the evidence artifact Default: ''.
        content_summary (str | Unset): Brief summary of evidence content Default: ''.
        source_system (str | Unset): System the evidence was pulled from Default: ''.
        collected_at (str | Unset): ISO timestamp when collected (defaults to now) Default: ''.
    """

    evidence_type: str | Unset = "document"
    filename: str | Unset = ""
    content_summary: str | Unset = ""
    source_system: str | Unset = ""
    collected_at: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        evidence_type = self.evidence_type

        filename = self.filename

        content_summary = self.content_summary

        source_system = self.source_system

        collected_at = self.collected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if evidence_type is not UNSET:
            field_dict["evidence_type"] = evidence_type
        if filename is not UNSET:
            field_dict["filename"] = filename
        if content_summary is not UNSET:
            field_dict["content_summary"] = content_summary
        if source_system is not UNSET:
            field_dict["source_system"] = source_system
        if collected_at is not UNSET:
            field_dict["collected_at"] = collected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        evidence_type = d.pop("evidence_type", UNSET)

        filename = d.pop("filename", UNSET)

        content_summary = d.pop("content_summary", UNSET)

        source_system = d.pop("source_system", UNSET)

        collected_at = d.pop("collected_at", UNSET)

        evidence_submit = cls(
            evidence_type=evidence_type,
            filename=filename,
            content_summary=content_summary,
            source_system=source_system,
            collected_at=collected_at,
        )

        evidence_submit.additional_properties = d
        return evidence_submit

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
