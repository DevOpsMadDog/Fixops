from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ScenarioListResponse")


@_attrs_define
class ScenarioListResponse:
    """
    Attributes:
        scenario_id (str):
        name (str):
        category (str):
        description (str):
        threat_actor (str):
        difficulty (str):
        estimated_duration_minutes (int):
        step_count (int):
        techniques (list[str]):
    """

    scenario_id: str
    name: str
    category: str
    description: str
    threat_actor: str
    difficulty: str
    estimated_duration_minutes: int
    step_count: int
    techniques: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario_id = self.scenario_id

        name = self.name

        category = self.category

        description = self.description

        threat_actor = self.threat_actor

        difficulty = self.difficulty

        estimated_duration_minutes = self.estimated_duration_minutes

        step_count = self.step_count

        techniques = self.techniques

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario_id": scenario_id,
                "name": name,
                "category": category,
                "description": description,
                "threat_actor": threat_actor,
                "difficulty": difficulty,
                "estimated_duration_minutes": estimated_duration_minutes,
                "step_count": step_count,
                "techniques": techniques,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario_id = d.pop("scenario_id")

        name = d.pop("name")

        category = d.pop("category")

        description = d.pop("description")

        threat_actor = d.pop("threat_actor")

        difficulty = d.pop("difficulty")

        estimated_duration_minutes = d.pop("estimated_duration_minutes")

        step_count = d.pop("step_count")

        techniques = cast(list[str], d.pop("techniques"))

        scenario_list_response = cls(
            scenario_id=scenario_id,
            name=name,
            category=category,
            description=description,
            threat_actor=threat_actor,
            difficulty=difficulty,
            estimated_duration_minutes=estimated_duration_minutes,
            step_count=step_count,
            techniques=techniques,
        )

        scenario_list_response.additional_properties = d
        return scenario_list_response

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
