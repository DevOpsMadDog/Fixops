from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessmentCreate")


@_attrs_define
class AssessmentCreate:
    """
    Attributes:
        model_id (str):
        score (float):
        assessment_type (str | Unset):  Default: 'performance'.
        findings (list[str] | Unset):
        assessor (str | Unset):  Default: ''.
    """

    model_id: str
    score: float
    assessment_type: str | Unset = "performance"
    findings: list[str] | Unset = UNSET
    assessor: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        model_id = self.model_id

        score = self.score

        assessment_type = self.assessment_type

        findings: list[str] | Unset = UNSET
        if not isinstance(self.findings, Unset):
            findings = self.findings

        assessor = self.assessor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "model_id": model_id,
                "score": score,
            }
        )
        if assessment_type is not UNSET:
            field_dict["assessment_type"] = assessment_type
        if findings is not UNSET:
            field_dict["findings"] = findings
        if assessor is not UNSET:
            field_dict["assessor"] = assessor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        model_id = d.pop("model_id")

        score = d.pop("score")

        assessment_type = d.pop("assessment_type", UNSET)

        findings = cast(list[str], d.pop("findings", UNSET))

        assessor = d.pop("assessor", UNSET)

        assessment_create = cls(
            model_id=model_id,
            score=score,
            assessment_type=assessment_type,
            findings=findings,
            assessor=assessor,
        )

        assessment_create.additional_properties = d
        return assessment_create

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
