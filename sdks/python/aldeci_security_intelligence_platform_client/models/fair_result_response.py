from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

T = TypeVar("T", bound="FAIRResultResponse")


@_attrs_define
class FAIRResultResponse:
    """FAIR simulation output.

    Attributes:
        scenario_name (str):
        ale_p10_usd (float):
        ale_p50_usd (float):
        ale_p90_usd (float):
        ale_mean_usd (float):
        max_single_loss_usd (float):
        loss_exceedance_probability (float):
        simulation_iterations (int):
        computed_at (datetime.datetime):
    """

    scenario_name: str
    ale_p10_usd: float
    ale_p50_usd: float
    ale_p90_usd: float
    ale_mean_usd: float
    max_single_loss_usd: float
    loss_exceedance_probability: float
    simulation_iterations: int
    computed_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario_name = self.scenario_name

        ale_p10_usd = self.ale_p10_usd

        ale_p50_usd = self.ale_p50_usd

        ale_p90_usd = self.ale_p90_usd

        ale_mean_usd = self.ale_mean_usd

        max_single_loss_usd = self.max_single_loss_usd

        loss_exceedance_probability = self.loss_exceedance_probability

        simulation_iterations = self.simulation_iterations

        computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario_name": scenario_name,
                "ale_p10_usd": ale_p10_usd,
                "ale_p50_usd": ale_p50_usd,
                "ale_p90_usd": ale_p90_usd,
                "ale_mean_usd": ale_mean_usd,
                "max_single_loss_usd": max_single_loss_usd,
                "loss_exceedance_probability": loss_exceedance_probability,
                "simulation_iterations": simulation_iterations,
                "computed_at": computed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario_name = d.pop("scenario_name")

        ale_p10_usd = d.pop("ale_p10_usd")

        ale_p50_usd = d.pop("ale_p50_usd")

        ale_p90_usd = d.pop("ale_p90_usd")

        ale_mean_usd = d.pop("ale_mean_usd")

        max_single_loss_usd = d.pop("max_single_loss_usd")

        loss_exceedance_probability = d.pop("loss_exceedance_probability")

        simulation_iterations = d.pop("simulation_iterations")

        computed_at = isoparse(d.pop("computed_at"))

        fair_result_response = cls(
            scenario_name=scenario_name,
            ale_p10_usd=ale_p10_usd,
            ale_p50_usd=ale_p50_usd,
            ale_p90_usd=ale_p90_usd,
            ale_mean_usd=ale_mean_usd,
            max_single_loss_usd=max_single_loss_usd,
            loss_exceedance_probability=loss_exceedance_probability,
            simulation_iterations=simulation_iterations,
            computed_at=computed_at,
        )

        fair_result_response.additional_properties = d
        return fair_result_response

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
