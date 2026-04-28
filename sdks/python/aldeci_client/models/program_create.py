from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProgramCreate")


@_attrs_define
class ProgramCreate:
    """
    Attributes:
        program_name (str):
        program_type (str):
        target_audience (str | Unset):  Default: 'all_staff'.
        duration_mins (int | Unset):  Default: 30.
        frequency (str | Unset):  Default: 'annual'.
        passing_score (int | Unset):  Default: 70.
    """

    program_name: str
    program_type: str
    target_audience: str | Unset = "all_staff"
    duration_mins: int | Unset = 30
    frequency: str | Unset = "annual"
    passing_score: int | Unset = 70
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        program_name = self.program_name

        program_type = self.program_type

        target_audience = self.target_audience

        duration_mins = self.duration_mins

        frequency = self.frequency

        passing_score = self.passing_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "program_name": program_name,
                "program_type": program_type,
            }
        )
        if target_audience is not UNSET:
            field_dict["target_audience"] = target_audience
        if duration_mins is not UNSET:
            field_dict["duration_mins"] = duration_mins
        if frequency is not UNSET:
            field_dict["frequency"] = frequency
        if passing_score is not UNSET:
            field_dict["passing_score"] = passing_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        program_name = d.pop("program_name")

        program_type = d.pop("program_type")

        target_audience = d.pop("target_audience", UNSET)

        duration_mins = d.pop("duration_mins", UNSET)

        frequency = d.pop("frequency", UNSET)

        passing_score = d.pop("passing_score", UNSET)

        program_create = cls(
            program_name=program_name,
            program_type=program_type,
            target_audience=target_audience,
            duration_mins=duration_mins,
            frequency=frequency,
            passing_score=passing_score,
        )

        program_create.additional_properties = d
        return program_create

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
