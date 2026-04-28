from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ScenarioResponse")


@_attrs_define
class ScenarioResponse:
    """Scenario response.

    Attributes:
        scenario_id (str):
        name (str):
        description (str):
        threat_actor (str):
        complexity (str):
        target_assets (list[str]):
        target_cves (list[str]):
        kill_chain_phases (list[str]):
        objectives (list[str]):
        created_at (str):
    """

    scenario_id: str
    name: str
    description: str
    threat_actor: str
    complexity: str
    target_assets: list[str]
    target_cves: list[str]
    kill_chain_phases: list[str]
    objectives: list[str]
    created_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario_id = self.scenario_id

        name = self.name

        description = self.description

        threat_actor = self.threat_actor

        complexity = self.complexity

        target_assets = self.target_assets

        target_cves = self.target_cves

        kill_chain_phases = self.kill_chain_phases

        objectives = self.objectives

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario_id": scenario_id,
                "name": name,
                "description": description,
                "threat_actor": threat_actor,
                "complexity": complexity,
                "target_assets": target_assets,
                "target_cves": target_cves,
                "kill_chain_phases": kill_chain_phases,
                "objectives": objectives,
                "created_at": created_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario_id = d.pop("scenario_id")

        name = d.pop("name")

        description = d.pop("description")

        threat_actor = d.pop("threat_actor")

        complexity = d.pop("complexity")

        target_assets = cast(list[str], d.pop("target_assets"))

        target_cves = cast(list[str], d.pop("target_cves"))

        kill_chain_phases = cast(list[str], d.pop("kill_chain_phases"))

        objectives = cast(list[str], d.pop("objectives"))

        created_at = d.pop("created_at")

        scenario_response = cls(
            scenario_id=scenario_id,
            name=name,
            description=description,
            threat_actor=threat_actor,
            complexity=complexity,
            target_assets=target_assets,
            target_cves=target_cves,
            kill_chain_phases=kill_chain_phases,
            objectives=objectives,
            created_at=created_at,
        )

        scenario_response.additional_properties = d
        return scenario_response

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
