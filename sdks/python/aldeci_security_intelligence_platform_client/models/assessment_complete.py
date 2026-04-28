from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessmentComplete")


@_attrs_define
class AssessmentComplete:
    """
    Attributes:
        score (float):
        findings_count (int | Unset):  Default: 0.
        critical_findings (int | Unset):  Default: 0.
        next_assessment (str | Unset):  Default: ''.
    """

    score: float
    findings_count: int | Unset = 0
    critical_findings: int | Unset = 0
    next_assessment: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        score = self.score

        findings_count = self.findings_count

        critical_findings = self.critical_findings

        next_assessment = self.next_assessment

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "score": score,
            }
        )
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if critical_findings is not UNSET:
            field_dict["critical_findings"] = critical_findings
        if next_assessment is not UNSET:
            field_dict["next_assessment"] = next_assessment

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        score = d.pop("score")

        findings_count = d.pop("findings_count", UNSET)

        critical_findings = d.pop("critical_findings", UNSET)

        next_assessment = d.pop("next_assessment", UNSET)

        assessment_complete = cls(
            score=score,
            findings_count=findings_count,
            critical_findings=critical_findings,
            next_assessment=next_assessment,
        )

        assessment_complete.additional_properties = d
        return assessment_complete

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
