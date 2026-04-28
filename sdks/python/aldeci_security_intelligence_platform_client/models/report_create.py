from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReportCreate")


@_attrs_define
class ReportCreate:
    """
    Attributes:
        title (str):
        intel_type (str | Unset):  Default: 'tactical'.
        tlp (str | Unset):  Default: 'amber'.
        source_type (str | Unset):  Default: 'osint'.
        summary (str | Unset):  Default: ''.
        content (str | Unset):  Default: ''.
        tags_json (list[str] | Unset):
        confidence_score (float | Unset):  Default: 0.5.
    """

    title: str
    intel_type: str | Unset = "tactical"
    tlp: str | Unset = "amber"
    source_type: str | Unset = "osint"
    summary: str | Unset = ""
    content: str | Unset = ""
    tags_json: list[str] | Unset = UNSET
    confidence_score: float | Unset = 0.5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        intel_type = self.intel_type

        tlp = self.tlp

        source_type = self.source_type

        summary = self.summary

        content = self.content

        tags_json: list[str] | Unset = UNSET
        if not isinstance(self.tags_json, Unset):
            tags_json = self.tags_json

        confidence_score = self.confidence_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if intel_type is not UNSET:
            field_dict["intel_type"] = intel_type
        if tlp is not UNSET:
            field_dict["tlp"] = tlp
        if source_type is not UNSET:
            field_dict["source_type"] = source_type
        if summary is not UNSET:
            field_dict["summary"] = summary
        if content is not UNSET:
            field_dict["content"] = content
        if tags_json is not UNSET:
            field_dict["tags_json"] = tags_json
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        intel_type = d.pop("intel_type", UNSET)

        tlp = d.pop("tlp", UNSET)

        source_type = d.pop("source_type", UNSET)

        summary = d.pop("summary", UNSET)

        content = d.pop("content", UNSET)

        tags_json = cast(list[str], d.pop("tags_json", UNSET))

        confidence_score = d.pop("confidence_score", UNSET)

        report_create = cls(
            title=title,
            intel_type=intel_type,
            tlp=tlp,
            source_type=source_type,
            summary=summary,
            content=content,
            tags_json=tags_json,
            confidence_score=confidence_score,
        )

        report_create.additional_properties = d
        return report_create

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
