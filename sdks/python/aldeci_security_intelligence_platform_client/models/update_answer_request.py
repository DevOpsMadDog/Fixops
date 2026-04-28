from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateAnswerRequest")


@_attrs_define
class UpdateAnswerRequest:
    """
    Attributes:
        answer (str): Answer text
        evidence_refs (list[str] | None | Unset): List of evidence/control references
    """

    answer: str
    evidence_refs: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        answer = self.answer

        evidence_refs: list[str] | None | Unset
        if isinstance(self.evidence_refs, Unset):
            evidence_refs = UNSET
        elif isinstance(self.evidence_refs, list):
            evidence_refs = self.evidence_refs

        else:
            evidence_refs = self.evidence_refs

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "answer": answer,
            }
        )
        if evidence_refs is not UNSET:
            field_dict["evidence_refs"] = evidence_refs

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
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

        update_answer_request = cls(
            answer=answer,
            evidence_refs=evidence_refs,
        )

        update_answer_request.additional_properties = d
        return update_answer_request

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
