from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.attack_scenario import AttackScenario

T = TypeVar("T", bound="RunSimulationRequest")


@_attrs_define
class RunSimulationRequest:
    """Request to run a breach simulation.

    Attributes:
        scenario (AttackScenario): Supported breach simulation scenarios.
        org_id (str): Organisation identifier
    """

    scenario: AttackScenario
    org_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario = self.scenario.value

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario": scenario,
                "org_id": org_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario = AttackScenario(d.pop("scenario"))

        org_id = d.pop("org_id")

        run_simulation_request = cls(
            scenario=scenario,
            org_id=org_id,
        )

        run_simulation_request.additional_properties = d
        return run_simulation_request

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
