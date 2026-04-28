from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExerciseCreate")


@_attrs_define
class ExerciseCreate:
    """
    Attributes:
        exercise_name (str):
        exercise_type (str):
        scheduled_date (str):
        scenario (str | Unset):  Default: ''.
        participants (int | Unset):  Default: 0.
    """

    exercise_name: str
    exercise_type: str
    scheduled_date: str
    scenario: str | Unset = ""
    participants: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        exercise_name = self.exercise_name

        exercise_type = self.exercise_type

        scheduled_date = self.scheduled_date

        scenario = self.scenario

        participants = self.participants

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "exercise_name": exercise_name,
                "exercise_type": exercise_type,
                "scheduled_date": scheduled_date,
            }
        )
        if scenario is not UNSET:
            field_dict["scenario"] = scenario
        if participants is not UNSET:
            field_dict["participants"] = participants

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        exercise_name = d.pop("exercise_name")

        exercise_type = d.pop("exercise_type")

        scheduled_date = d.pop("scheduled_date")

        scenario = d.pop("scenario", UNSET)

        participants = d.pop("participants", UNSET)

        exercise_create = cls(
            exercise_name=exercise_name,
            exercise_type=exercise_type,
            scheduled_date=scheduled_date,
            scenario=scenario,
            participants=participants,
        )

        exercise_create.additional_properties = d
        return exercise_create

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
