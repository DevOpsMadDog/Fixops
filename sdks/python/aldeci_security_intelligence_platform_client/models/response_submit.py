from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResponseSubmit")


@_attrs_define
class ResponseSubmit:
    """
    Attributes:
        question_id (str):
        response_text (str | Unset):  Default: ''.
        response_value (int | Unset):  Default: 0.
    """

    question_id: str
    response_text: str | Unset = ""
    response_value: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        question_id = self.question_id

        response_text = self.response_text

        response_value = self.response_value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "question_id": question_id,
            }
        )
        if response_text is not UNSET:
            field_dict["response_text"] = response_text
        if response_value is not UNSET:
            field_dict["response_value"] = response_value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        question_id = d.pop("question_id")

        response_text = d.pop("response_text", UNSET)

        response_value = d.pop("response_value", UNSET)

        response_submit = cls(
            question_id=question_id,
            response_text=response_text,
            response_value=response_value,
        )

        response_submit.additional_properties = d
        return response_submit

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
