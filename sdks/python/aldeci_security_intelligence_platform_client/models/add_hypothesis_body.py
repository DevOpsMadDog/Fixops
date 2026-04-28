from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddHypothesisBody")


@_attrs_define
class AddHypothesisBody:
    """
    Attributes:
        hypothesis_text (str): Hypothesis statement
        confidence (str | Unset): high | medium | low Default: 'medium'.
    """

    hypothesis_text: str
    confidence: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hypothesis_text = self.hypothesis_text

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hypothesis_text": hypothesis_text,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        hypothesis_text = d.pop("hypothesis_text")

        confidence = d.pop("confidence", UNSET)

        add_hypothesis_body = cls(
            hypothesis_text=hypothesis_text,
            confidence=confidence,
        )

        add_hypothesis_body.additional_properties = d
        return add_hypothesis_body

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
