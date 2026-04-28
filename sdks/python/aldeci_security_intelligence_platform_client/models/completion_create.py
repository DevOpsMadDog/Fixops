from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CompletionCreate")


@_attrs_define
class CompletionCreate:
    """
    Attributes:
        user_id (str):
        challenge_id (str):
        score (float | Unset):  Default: 0.0.
        time_spent_seconds (int | Unset):  Default: 0.
        passed (bool | Unset):  Default: False.
    """

    user_id: str
    challenge_id: str
    score: float | Unset = 0.0
    time_spent_seconds: int | Unset = 0
    passed: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        challenge_id = self.challenge_id

        score = self.score

        time_spent_seconds = self.time_spent_seconds

        passed = self.passed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "challenge_id": challenge_id,
            }
        )
        if score is not UNSET:
            field_dict["score"] = score
        if time_spent_seconds is not UNSET:
            field_dict["time_spent_seconds"] = time_spent_seconds
        if passed is not UNSET:
            field_dict["passed"] = passed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        challenge_id = d.pop("challenge_id")

        score = d.pop("score", UNSET)

        time_spent_seconds = d.pop("time_spent_seconds", UNSET)

        passed = d.pop("passed", UNSET)

        completion_create = cls(
            user_id=user_id,
            challenge_id=challenge_id,
            score=score,
            time_spent_seconds=time_spent_seconds,
            passed=passed,
        )

        completion_create.additional_properties = d
        return completion_create

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
