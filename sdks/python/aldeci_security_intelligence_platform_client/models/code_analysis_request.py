from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CodeAnalysisRequest")


@_attrs_define
class CodeAnalysisRequest:
    """Request model for code analysis.

    Attributes:
        file_path (str):
        content (str):
        language (str):
        include_metrics (bool | Unset):  Default: True.
        include_suggestions (bool | Unset):  Default: True.
        severity_threshold (None | str | Unset):
    """

    file_path: str
    content: str
    language: str
    include_metrics: bool | Unset = True
    include_suggestions: bool | Unset = True
    severity_threshold: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file_path = self.file_path

        content = self.content

        language = self.language

        include_metrics = self.include_metrics

        include_suggestions = self.include_suggestions

        severity_threshold: None | str | Unset
        if isinstance(self.severity_threshold, Unset):
            severity_threshold = UNSET
        else:
            severity_threshold = self.severity_threshold

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file_path": file_path,
                "content": content,
                "language": language,
            }
        )
        if include_metrics is not UNSET:
            field_dict["include_metrics"] = include_metrics
        if include_suggestions is not UNSET:
            field_dict["include_suggestions"] = include_suggestions
        if severity_threshold is not UNSET:
            field_dict["severity_threshold"] = severity_threshold

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file_path = d.pop("file_path")

        content = d.pop("content")

        language = d.pop("language")

        include_metrics = d.pop("include_metrics", UNSET)

        include_suggestions = d.pop("include_suggestions", UNSET)

        def _parse_severity_threshold(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity_threshold = _parse_severity_threshold(d.pop("severity_threshold", UNSET))

        code_analysis_request = cls(
            file_path=file_path,
            content=content,
            language=language,
            include_metrics=include_metrics,
            include_suggestions=include_suggestions,
            severity_threshold=severity_threshold,
        )

        code_analysis_request.additional_properties = d
        return code_analysis_request

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
