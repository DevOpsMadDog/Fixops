from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.assessment_response_category_scores import AssessmentResponseCategoryScores


T = TypeVar("T", bound="AssessmentResponse")


@_attrs_define
class AssessmentResponse:
    """Vendor assessment result.

    Attributes:
        id (str):
        vendor_id (str):
        questionnaire_score (float):
        category_scores (AssessmentResponseCategoryScores):
        question_count (int):
        submitted_at (str):
        next_review_date (None | str):
        assessed_by (str):
    """

    id: str
    vendor_id: str
    questionnaire_score: float
    category_scores: AssessmentResponseCategoryScores
    question_count: int
    submitted_at: str
    next_review_date: None | str
    assessed_by: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        vendor_id = self.vendor_id

        questionnaire_score = self.questionnaire_score

        category_scores = self.category_scores.to_dict()

        question_count = self.question_count

        submitted_at = self.submitted_at

        next_review_date: None | str
        next_review_date = self.next_review_date

        assessed_by = self.assessed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "vendor_id": vendor_id,
                "questionnaire_score": questionnaire_score,
                "category_scores": category_scores,
                "question_count": question_count,
                "submitted_at": submitted_at,
                "next_review_date": next_review_date,
                "assessed_by": assessed_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.assessment_response_category_scores import AssessmentResponseCategoryScores

        d = dict(src_dict)
        id = d.pop("id")

        vendor_id = d.pop("vendor_id")

        questionnaire_score = d.pop("questionnaire_score")

        category_scores = AssessmentResponseCategoryScores.from_dict(d.pop("category_scores"))

        question_count = d.pop("question_count")

        submitted_at = d.pop("submitted_at")

        def _parse_next_review_date(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        next_review_date = _parse_next_review_date(d.pop("next_review_date"))

        assessed_by = d.pop("assessed_by")

        assessment_response = cls(
            id=id,
            vendor_id=vendor_id,
            questionnaire_score=questionnaire_score,
            category_scores=category_scores,
            question_count=question_count,
            submitted_at=submitted_at,
            next_review_date=next_review_date,
            assessed_by=assessed_by,
        )

        assessment_response.additional_properties = d
        return assessment_response

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
