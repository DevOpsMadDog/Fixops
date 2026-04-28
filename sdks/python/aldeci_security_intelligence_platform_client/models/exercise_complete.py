from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExerciseComplete")


@_attrs_define
class ExerciseComplete:
    """
    Attributes:
        findings_count (int | Unset):  Default: 0.
        gaps_identified (list[str] | Unset):
        lessons_learned (list[str] | Unset):
    """

    findings_count: int | Unset = 0
    gaps_identified: list[str] | Unset = UNSET
    lessons_learned: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings_count = self.findings_count

        gaps_identified: list[str] | Unset = UNSET
        if not isinstance(self.gaps_identified, Unset):
            gaps_identified = self.gaps_identified

        lessons_learned: list[str] | Unset = UNSET
        if not isinstance(self.lessons_learned, Unset):
            lessons_learned = self.lessons_learned

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if gaps_identified is not UNSET:
            field_dict["gaps_identified"] = gaps_identified
        if lessons_learned is not UNSET:
            field_dict["lessons_learned"] = lessons_learned

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        findings_count = d.pop("findings_count", UNSET)

        gaps_identified = cast(list[str], d.pop("gaps_identified", UNSET))

        lessons_learned = cast(list[str], d.pop("lessons_learned", UNSET))

        exercise_complete = cls(
            findings_count=findings_count,
            gaps_identified=gaps_identified,
            lessons_learned=lessons_learned,
        )

        exercise_complete.additional_properties = d
        return exercise_complete

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
