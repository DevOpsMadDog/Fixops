from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.question_category import QuestionCategory
from ..types import UNSET, Unset

T = TypeVar("T", bound="AddAnswerBankRequest")


@_attrs_define
class AddAnswerBankRequest:
    """
    Attributes:
        question_key (str): Canonical question text (lowercase)
        category (QuestionCategory):
        answer (str):
        evidence_refs (list[str] | None | Unset):
        confidence (float | Unset):  Default: 1.0.
        org_id (str | Unset):  Default: 'default'.
    """

    question_key: str
    category: QuestionCategory
    answer: str
    evidence_refs: list[str] | None | Unset = UNSET
    confidence: float | Unset = 1.0
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        question_key = self.question_key

        category = self.category.value

        answer = self.answer

        evidence_refs: list[str] | None | Unset
        if isinstance(self.evidence_refs, Unset):
            evidence_refs = UNSET
        elif isinstance(self.evidence_refs, list):
            evidence_refs = self.evidence_refs

        else:
            evidence_refs = self.evidence_refs

        confidence = self.confidence

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "question_key": question_key,
                "category": category,
                "answer": answer,
            }
        )
        if evidence_refs is not UNSET:
            field_dict["evidence_refs"] = evidence_refs
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        question_key = d.pop("question_key")

        category = QuestionCategory(d.pop("category"))

        answer = d.pop("answer")

        def _parse_evidence_refs(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                evidence_refs_type_0 = cast(list[str], data)

                return evidence_refs_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        evidence_refs = _parse_evidence_refs(d.pop("evidence_refs", UNSET))

        confidence = d.pop("confidence", UNSET)

        org_id = d.pop("org_id", UNSET)

        add_answer_bank_request = cls(
            question_key=question_key,
            category=category,
            answer=answer,
            evidence_refs=evidence_refs,
            confidence=confidence,
            org_id=org_id,
        )

        add_answer_bank_request.additional_properties = d
        return add_answer_bank_request

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
