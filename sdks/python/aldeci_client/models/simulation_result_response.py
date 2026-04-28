from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="SimulationResultResponse")


@_attrs_define
class SimulationResultResponse:
    """API response for a simulation result.

    Attributes:
        id (str):
        scenario (str):
        steps_executed (int):
        steps_blocked (int):
        detection_time_seconds (float):
        containment_time_seconds (float):
        data_at_risk (str):
        defenses_tested (list[str]):
        gaps_found (list[str]):
        score (float):
        org_id (str):
        simulated_at (str):
    """

    id: str
    scenario: str
    steps_executed: int
    steps_blocked: int
    detection_time_seconds: float
    containment_time_seconds: float
    data_at_risk: str
    defenses_tested: list[str]
    gaps_found: list[str]
    score: float
    org_id: str
    simulated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        scenario = self.scenario

        steps_executed = self.steps_executed

        steps_blocked = self.steps_blocked

        detection_time_seconds = self.detection_time_seconds

        containment_time_seconds = self.containment_time_seconds

        data_at_risk = self.data_at_risk

        defenses_tested = self.defenses_tested

        gaps_found = self.gaps_found

        score = self.score

        org_id = self.org_id

        simulated_at = self.simulated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "scenario": scenario,
                "steps_executed": steps_executed,
                "steps_blocked": steps_blocked,
                "detection_time_seconds": detection_time_seconds,
                "containment_time_seconds": containment_time_seconds,
                "data_at_risk": data_at_risk,
                "defenses_tested": defenses_tested,
                "gaps_found": gaps_found,
                "score": score,
                "org_id": org_id,
                "simulated_at": simulated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        scenario = d.pop("scenario")

        steps_executed = d.pop("steps_executed")

        steps_blocked = d.pop("steps_blocked")

        detection_time_seconds = d.pop("detection_time_seconds")

        containment_time_seconds = d.pop("containment_time_seconds")

        data_at_risk = d.pop("data_at_risk")

        defenses_tested = cast(list[str], d.pop("defenses_tested"))

        gaps_found = cast(list[str], d.pop("gaps_found"))

        score = d.pop("score")

        org_id = d.pop("org_id")

        simulated_at = d.pop("simulated_at")

        simulation_result_response = cls(
            id=id,
            scenario=scenario,
            steps_executed=steps_executed,
            steps_blocked=steps_blocked,
            detection_time_seconds=detection_time_seconds,
            containment_time_seconds=containment_time_seconds,
            data_at_risk=data_at_risk,
            defenses_tested=defenses_tested,
            gaps_found=gaps_found,
            score=score,
            org_id=org_id,
            simulated_at=simulated_at,
        )

        simulation_result_response.additional_properties = d
        return simulation_result_response

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
