from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ParticipantCreate")


@_attrs_define
class ParticipantCreate:
    """
    Attributes:
        exercise_id (str):
        name (str):
        role (str | Unset):  Default: ''.
        department (str | Unset):  Default: ''.
        attended (bool | Unset):  Default: True.
        performance_score (float | Unset):  Default: 0.0.
    """

    exercise_id: str
    name: str
    role: str | Unset = ""
    department: str | Unset = ""
    attended: bool | Unset = True
    performance_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        exercise_id = self.exercise_id

        name = self.name

        role = self.role

        department = self.department

        attended = self.attended

        performance_score = self.performance_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "exercise_id": exercise_id,
                "name": name,
            }
        )
        if role is not UNSET:
            field_dict["role"] = role
        if department is not UNSET:
            field_dict["department"] = department
        if attended is not UNSET:
            field_dict["attended"] = attended
        if performance_score is not UNSET:
            field_dict["performance_score"] = performance_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        exercise_id = d.pop("exercise_id")

        name = d.pop("name")

        role = d.pop("role", UNSET)

        department = d.pop("department", UNSET)

        attended = d.pop("attended", UNSET)

        performance_score = d.pop("performance_score", UNSET)

        participant_create = cls(
            exercise_id=exercise_id,
            name=name,
            role=role,
            department=department,
            attended=attended,
            performance_score=performance_score,
        )

        participant_create.additional_properties = d
        return participant_create

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
