from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="DefenseCoverage")


@_attrs_define
class DefenseCoverage:
    """Defense coverage summary for an org.

    Attributes:
        org_id (str):
        total_simulations (int):
        scenarios_tested (list[str]):
        scenarios_not_tested (list[str]):
        average_score (float):
        weakest_scenario (None | str):
        strongest_scenario (None | str):
        coverage_percent (float):
    """

    org_id: str
    total_simulations: int
    scenarios_tested: list[str]
    scenarios_not_tested: list[str]
    average_score: float
    weakest_scenario: None | str
    strongest_scenario: None | str
    coverage_percent: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total_simulations = self.total_simulations

        scenarios_tested = self.scenarios_tested

        scenarios_not_tested = self.scenarios_not_tested

        average_score = self.average_score

        weakest_scenario: None | str
        weakest_scenario = self.weakest_scenario

        strongest_scenario: None | str
        strongest_scenario = self.strongest_scenario

        coverage_percent = self.coverage_percent

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total_simulations": total_simulations,
                "scenarios_tested": scenarios_tested,
                "scenarios_not_tested": scenarios_not_tested,
                "average_score": average_score,
                "weakest_scenario": weakest_scenario,
                "strongest_scenario": strongest_scenario,
                "coverage_percent": coverage_percent,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        total_simulations = d.pop("total_simulations")

        scenarios_tested = cast(list[str], d.pop("scenarios_tested"))

        scenarios_not_tested = cast(list[str], d.pop("scenarios_not_tested"))

        average_score = d.pop("average_score")

        def _parse_weakest_scenario(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        weakest_scenario = _parse_weakest_scenario(d.pop("weakest_scenario"))

        def _parse_strongest_scenario(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        strongest_scenario = _parse_strongest_scenario(d.pop("strongest_scenario"))

        coverage_percent = d.pop("coverage_percent")

        defense_coverage = cls(
            org_id=org_id,
            total_simulations=total_simulations,
            scenarios_tested=scenarios_tested,
            scenarios_not_tested=scenarios_not_tested,
            average_score=average_score,
            weakest_scenario=weakest_scenario,
            strongest_scenario=strongest_scenario,
            coverage_percent=coverage_percent,
        )

        defense_coverage.additional_properties = d
        return defense_coverage

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
