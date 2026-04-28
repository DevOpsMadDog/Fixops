from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCourseRequest")


@_attrs_define
class CreateCourseRequest:
    """
    Attributes:
        title (str):
        description (str | Unset):  Default: ''.
        category (str | Unset):  Default: 'compliance'.
        duration_minutes (int | Unset):  Default: 30.
        difficulty (str | Unset):  Default: 'beginner'.
        format_ (str | Unset):  Default: 'video'.
        passing_score (int | Unset):  Default: 70.
    """

    title: str
    description: str | Unset = ""
    category: str | Unset = "compliance"
    duration_minutes: int | Unset = 30
    difficulty: str | Unset = "beginner"
    format_: str | Unset = "video"
    passing_score: int | Unset = 70
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        category = self.category

        duration_minutes = self.duration_minutes

        difficulty = self.difficulty

        format_ = self.format_

        passing_score = self.passing_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if category is not UNSET:
            field_dict["category"] = category
        if duration_minutes is not UNSET:
            field_dict["duration_minutes"] = duration_minutes
        if difficulty is not UNSET:
            field_dict["difficulty"] = difficulty
        if format_ is not UNSET:
            field_dict["format"] = format_
        if passing_score is not UNSET:
            field_dict["passing_score"] = passing_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description", UNSET)

        category = d.pop("category", UNSET)

        duration_minutes = d.pop("duration_minutes", UNSET)

        difficulty = d.pop("difficulty", UNSET)

        format_ = d.pop("format", UNSET)

        passing_score = d.pop("passing_score", UNSET)

        create_course_request = cls(
            title=title,
            description=description,
            category=category,
            duration_minutes=duration_minutes,
            difficulty=difficulty,
            format_=format_,
            passing_score=passing_score,
        )

        create_course_request.additional_properties = d
        return create_course_request

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
