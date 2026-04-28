from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="QuestionnaireResponse")


@_attrs_define
class QuestionnaireResponse:
    """Vendor's response to a single assessment question.

    Attributes:
        question_id (str):
        answer (bool): True = Yes, False = No
        evidence_url (None | str | Unset): URL to supporting evidence
        notes (None | str | Unset): Vendor-provided notes
    """

    question_id: str
    answer: bool
    evidence_url: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        question_id = self.question_id

        answer = self.answer

        evidence_url: None | str | Unset
        if isinstance(self.evidence_url, Unset):
            evidence_url = UNSET
        else:
            evidence_url = self.evidence_url

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "question_id": question_id,
                "answer": answer,
            }
        )
        if evidence_url is not UNSET:
            field_dict["evidence_url"] = evidence_url
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        question_id = d.pop("question_id")

        answer = d.pop("answer")

        def _parse_evidence_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        evidence_url = _parse_evidence_url(d.pop("evidence_url", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        questionnaire_response = cls(
            question_id=question_id,
            answer=answer,
            evidence_url=evidence_url,
            notes=notes,
        )

        questionnaire_response.additional_properties = d
        return questionnaire_response

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
