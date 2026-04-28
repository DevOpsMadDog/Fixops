from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordParticipationRequest")


@_attrs_define
class RecordParticipationRequest:
    """
    Attributes:
        user_id (str): User ID of the participant
        result (str): pass | fail | incomplete | click | report
        department (None | str | Unset):
        score (float | None | Unset):  Default: 0.0.
        completed_at (None | str | Unset):
        time_spent_minutes (float | None | Unset):  Default: 0.0.
    """

    user_id: str
    result: str
    department: None | str | Unset = UNSET
    score: float | None | Unset = 0.0
    completed_at: None | str | Unset = UNSET
    time_spent_minutes: float | None | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        result = self.result

        department: None | str | Unset
        if isinstance(self.department, Unset):
            department = UNSET
        else:
            department = self.department

        score: float | None | Unset
        if isinstance(self.score, Unset):
            score = UNSET
        else:
            score = self.score

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        time_spent_minutes: float | None | Unset
        if isinstance(self.time_spent_minutes, Unset):
            time_spent_minutes = UNSET
        else:
            time_spent_minutes = self.time_spent_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "result": result,
            }
        )
        if department is not UNSET:
            field_dict["department"] = department
        if score is not UNSET:
            field_dict["score"] = score
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if time_spent_minutes is not UNSET:
            field_dict["time_spent_minutes"] = time_spent_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        result = d.pop("result")

        def _parse_department(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        department = _parse_department(d.pop("department", UNSET))

        def _parse_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        score = _parse_score(d.pop("score", UNSET))

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        def _parse_time_spent_minutes(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        time_spent_minutes = _parse_time_spent_minutes(d.pop("time_spent_minutes", UNSET))

        record_participation_request = cls(
            user_id=user_id,
            result=result,
            department=department,
            score=score,
            completed_at=completed_at,
            time_spent_minutes=time_spent_minutes,
        )

        record_participation_request.additional_properties = d
        return record_participation_request

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
