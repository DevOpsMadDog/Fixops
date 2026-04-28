from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChallengeCreate")


@_attrs_define
class ChallengeCreate:
    """
    Attributes:
        title (str):
        challenge_type (str | Unset):  Default: 'quiz'.
        difficulty (str | Unset):  Default: 'medium'.
        points (int | Unset):  Default: 10.
        department (str | Unset):  Default: ''.
    """

    title: str
    challenge_type: str | Unset = "quiz"
    difficulty: str | Unset = "medium"
    points: int | Unset = 10
    department: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        challenge_type = self.challenge_type

        difficulty = self.difficulty

        points = self.points

        department = self.department

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if challenge_type is not UNSET:
            field_dict["challenge_type"] = challenge_type
        if difficulty is not UNSET:
            field_dict["difficulty"] = difficulty
        if points is not UNSET:
            field_dict["points"] = points
        if department is not UNSET:
            field_dict["department"] = department

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        challenge_type = d.pop("challenge_type", UNSET)

        difficulty = d.pop("difficulty", UNSET)

        points = d.pop("points", UNSET)

        department = d.pop("department", UNSET)

        challenge_create = cls(
            title=title,
            challenge_type=challenge_type,
            difficulty=difficulty,
            points=points,
            department=department,
        )

        challenge_create.additional_properties = d
        return challenge_create

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
