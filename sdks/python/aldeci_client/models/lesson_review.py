from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LessonReview")


@_attrs_define
class LessonReview:
    """
    Attributes:
        reviewer (str):
        outcome (str):
        notes (str | Unset):  Default: ''.
    """

    reviewer: str
    outcome: str
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        reviewer = self.reviewer

        outcome = self.outcome

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "reviewer": reviewer,
                "outcome": outcome,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        reviewer = d.pop("reviewer")

        outcome = d.pop("outcome")

        notes = d.pop("notes", UNSET)

        lesson_review = cls(
            reviewer=reviewer,
            outcome=outcome,
            notes=notes,
        )

        lesson_review.additional_properties = d
        return lesson_review

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
