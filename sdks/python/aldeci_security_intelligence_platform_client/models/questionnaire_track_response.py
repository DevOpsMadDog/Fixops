from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="QuestionnaireTrackResponse")


@_attrs_define
class QuestionnaireTrackResponse:
    """Response after creating a questionnaire tracking record.

    Attributes:
        questionnaire_id (str):
        vendor_id (str):
        status (str):
        question_count (int):
    """

    questionnaire_id: str
    vendor_id: str
    status: str
    question_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        questionnaire_id = self.questionnaire_id

        vendor_id = self.vendor_id

        status = self.status

        question_count = self.question_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "questionnaire_id": questionnaire_id,
                "vendor_id": vendor_id,
                "status": status,
                "question_count": question_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        questionnaire_id = d.pop("questionnaire_id")

        vendor_id = d.pop("vendor_id")

        status = d.pop("status")

        question_count = d.pop("question_count")

        questionnaire_track_response = cls(
            questionnaire_id=questionnaire_id,
            vendor_id=vendor_id,
            status=status,
            question_count=question_count,
        )

        questionnaire_track_response.additional_properties = d
        return questionnaire_track_response

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
