from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="QuestionCreate")


@_attrs_define
class QuestionCreate:
    """
    Attributes:
        question_text (str):
        question_category (str | Unset):  Default: 'governance'.
        weight (float | Unset):  Default: 1.0.
        required (bool | Unset):  Default: True.
    """

    question_text: str
    question_category: str | Unset = "governance"
    weight: float | Unset = 1.0
    required: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        question_text = self.question_text

        question_category = self.question_category

        weight = self.weight

        required = self.required

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "question_text": question_text,
            }
        )
        if question_category is not UNSET:
            field_dict["question_category"] = question_category
        if weight is not UNSET:
            field_dict["weight"] = weight
        if required is not UNSET:
            field_dict["required"] = required

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        question_text = d.pop("question_text")

        question_category = d.pop("question_category", UNSET)

        weight = d.pop("weight", UNSET)

        required = d.pop("required", UNSET)

        question_create = cls(
            question_text=question_text,
            question_category=question_category,
            weight=weight,
            required=required,
        )

        question_create.additional_properties = d
        return question_create

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
