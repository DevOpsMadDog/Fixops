from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.code_metrics import CodeMetrics
    from ..models.finding import Finding
    from ..models.suggestion import Suggestion


T = TypeVar("T", bound="CodeAnalysisResponse")


@_attrs_define
class CodeAnalysisResponse:
    """Response model for code analysis.

    Attributes:
        findings (list[Finding]):
        suggestions (list[Suggestion]):
        metrics (CodeMetrics): Code quality metrics.
        analysis_time_ms (float):
        file_hash (str):
    """

    findings: list[Finding]
    suggestions: list[Suggestion]
    metrics: CodeMetrics
    analysis_time_ms: float
    file_hash: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        suggestions = []
        for suggestions_item_data in self.suggestions:
            suggestions_item = suggestions_item_data.to_dict()
            suggestions.append(suggestions_item)

        metrics = self.metrics.to_dict()

        analysis_time_ms = self.analysis_time_ms

        file_hash = self.file_hash

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
                "suggestions": suggestions,
                "metrics": metrics,
                "analysis_time_ms": analysis_time_ms,
                "file_hash": file_hash,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.code_metrics import CodeMetrics
        from ..models.finding import Finding
        from ..models.suggestion import Suggestion

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = Finding.from_dict(findings_item_data)

            findings.append(findings_item)

        suggestions = []
        _suggestions = d.pop("suggestions")
        for suggestions_item_data in _suggestions:
            suggestions_item = Suggestion.from_dict(suggestions_item_data)

            suggestions.append(suggestions_item)

        metrics = CodeMetrics.from_dict(d.pop("metrics"))

        analysis_time_ms = d.pop("analysis_time_ms")

        file_hash = d.pop("file_hash")

        code_analysis_response = cls(
            findings=findings,
            suggestions=suggestions,
            metrics=metrics,
            analysis_time_ms=analysis_time_ms,
            file_hash=file_hash,
        )

        code_analysis_response.additional_properties = d
        return code_analysis_response

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
