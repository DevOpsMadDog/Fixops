from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ExerciseSummaryResponse")


@_attrs_define
class ExerciseSummaryResponse:
    """
    Attributes:
        exercise_id (str):
        name (str):
        scenario_name (str):
        category (str):
        status (str):
        scope (str):
        step_count (int):
        steps_executed (int):
        steps_detected (int):
        created_at (str):
        started_at (None | str):
        completed_at (None | str):
        tags (list[str]):
    """

    exercise_id: str
    name: str
    scenario_name: str
    category: str
    status: str
    scope: str
    step_count: int
    steps_executed: int
    steps_detected: int
    created_at: str
    started_at: None | str
    completed_at: None | str
    tags: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        exercise_id = self.exercise_id

        name = self.name

        scenario_name = self.scenario_name

        category = self.category

        status = self.status

        scope = self.scope

        step_count = self.step_count

        steps_executed = self.steps_executed

        steps_detected = self.steps_detected

        created_at = self.created_at

        started_at: None | str
        started_at = self.started_at

        completed_at: None | str
        completed_at = self.completed_at

        tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "exercise_id": exercise_id,
                "name": name,
                "scenario_name": scenario_name,
                "category": category,
                "status": status,
                "scope": scope,
                "step_count": step_count,
                "steps_executed": steps_executed,
                "steps_detected": steps_detected,
                "created_at": created_at,
                "started_at": started_at,
                "completed_at": completed_at,
                "tags": tags,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        exercise_id = d.pop("exercise_id")

        name = d.pop("name")

        scenario_name = d.pop("scenario_name")

        category = d.pop("category")

        status = d.pop("status")

        scope = d.pop("scope")

        step_count = d.pop("step_count")

        steps_executed = d.pop("steps_executed")

        steps_detected = d.pop("steps_detected")

        created_at = d.pop("created_at")

        def _parse_started_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        started_at = _parse_started_at(d.pop("started_at"))

        def _parse_completed_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        completed_at = _parse_completed_at(d.pop("completed_at"))

        tags = cast(list[str], d.pop("tags"))

        exercise_summary_response = cls(
            exercise_id=exercise_id,
            name=name,
            scenario_name=scenario_name,
            category=category,
            status=status,
            scope=scope,
            step_count=step_count,
            steps_executed=steps_executed,
            steps_detected=steps_detected,
            created_at=created_at,
            started_at=started_at,
            completed_at=completed_at,
            tags=tags,
        )

        exercise_summary_response.additional_properties = d
        return exercise_summary_response

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
