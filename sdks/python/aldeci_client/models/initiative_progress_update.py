from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="InitiativeProgressUpdate")


@_attrs_define
class InitiativeProgressUpdate:
    """
    Attributes:
        participants (int):
        completion_rate (float):
        impact_score (float):
    """

    participants: int
    completion_rate: float
    impact_score: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        participants = self.participants

        completion_rate = self.completion_rate

        impact_score = self.impact_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "participants": participants,
                "completion_rate": completion_rate,
                "impact_score": impact_score,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        participants = d.pop("participants")

        completion_rate = d.pop("completion_rate")

        impact_score = d.pop("impact_score")

        initiative_progress_update = cls(
            participants=participants,
            completion_rate=completion_rate,
            impact_score=impact_score,
        )

        initiative_progress_update.additional_properties = d
        return initiative_progress_update

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
