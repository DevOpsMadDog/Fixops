from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FAIRScenarioRequest")


@_attrs_define
class FAIRScenarioRequest:
    """Input for a single FAIR risk scenario.

    Attributes:
        scenario_name (str): Human-readable scenario label
        threat_event_frequency_per_year (float): Expected threat events per year
        vulnerability_probability (float): Probability of successful exploit [0.0, 1.0]
        primary_loss_min_usd (float): Minimum primary loss magnitude (USD)
        primary_loss_max_usd (float): Maximum primary loss magnitude (USD)
        secondary_loss_min_usd (float | Unset): Minimum secondary loss (regulatory, reputational) (USD) Default: 0.0.
        secondary_loss_max_usd (float | Unset): Maximum secondary loss magnitude (USD) Default: 0.0.
        monte_carlo_iterations (int | Unset): Monte Carlo sample count (100–10000) Default: 1000.
    """

    scenario_name: str
    threat_event_frequency_per_year: float
    vulnerability_probability: float
    primary_loss_min_usd: float
    primary_loss_max_usd: float
    secondary_loss_min_usd: float | Unset = 0.0
    secondary_loss_max_usd: float | Unset = 0.0
    monte_carlo_iterations: int | Unset = 1000
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario_name = self.scenario_name

        threat_event_frequency_per_year = self.threat_event_frequency_per_year

        vulnerability_probability = self.vulnerability_probability

        primary_loss_min_usd = self.primary_loss_min_usd

        primary_loss_max_usd = self.primary_loss_max_usd

        secondary_loss_min_usd = self.secondary_loss_min_usd

        secondary_loss_max_usd = self.secondary_loss_max_usd

        monte_carlo_iterations = self.monte_carlo_iterations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario_name": scenario_name,
                "threat_event_frequency_per_year": threat_event_frequency_per_year,
                "vulnerability_probability": vulnerability_probability,
                "primary_loss_min_usd": primary_loss_min_usd,
                "primary_loss_max_usd": primary_loss_max_usd,
            }
        )
        if secondary_loss_min_usd is not UNSET:
            field_dict["secondary_loss_min_usd"] = secondary_loss_min_usd
        if secondary_loss_max_usd is not UNSET:
            field_dict["secondary_loss_max_usd"] = secondary_loss_max_usd
        if monte_carlo_iterations is not UNSET:
            field_dict["monte_carlo_iterations"] = monte_carlo_iterations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario_name = d.pop("scenario_name")

        threat_event_frequency_per_year = d.pop("threat_event_frequency_per_year")

        vulnerability_probability = d.pop("vulnerability_probability")

        primary_loss_min_usd = d.pop("primary_loss_min_usd")

        primary_loss_max_usd = d.pop("primary_loss_max_usd")

        secondary_loss_min_usd = d.pop("secondary_loss_min_usd", UNSET)

        secondary_loss_max_usd = d.pop("secondary_loss_max_usd", UNSET)

        monte_carlo_iterations = d.pop("monte_carlo_iterations", UNSET)

        fair_scenario_request = cls(
            scenario_name=scenario_name,
            threat_event_frequency_per_year=threat_event_frequency_per_year,
            vulnerability_probability=vulnerability_probability,
            primary_loss_min_usd=primary_loss_min_usd,
            primary_loss_max_usd=primary_loss_max_usd,
            secondary_loss_min_usd=secondary_loss_min_usd,
            secondary_loss_max_usd=secondary_loss_max_usd,
            monte_carlo_iterations=monte_carlo_iterations,
        )

        fair_scenario_request.additional_properties = d
        return fair_scenario_request

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
