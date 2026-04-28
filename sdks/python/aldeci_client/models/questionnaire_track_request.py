from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.questionnaire_track_request_questions import QuestionnaireTrackRequestQuestions


T = TypeVar("T", bound="QuestionnaireTrackRequest")


@_attrs_define
class QuestionnaireTrackRequest:
    """Request body for tracking a vendor security questionnaire.

    Attributes:
        questions (QuestionnaireTrackRequestQuestions): Map of question_id -> question text or response data
    """

    questions: QuestionnaireTrackRequestQuestions
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        questions = self.questions.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "questions": questions,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.questionnaire_track_request_questions import QuestionnaireTrackRequestQuestions

        d = dict(src_dict)
        questions = QuestionnaireTrackRequestQuestions.from_dict(d.pop("questions"))

        questionnaire_track_request = cls(
            questions=questions,
        )

        questionnaire_track_request.additional_properties = d
        return questionnaire_track_request

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
