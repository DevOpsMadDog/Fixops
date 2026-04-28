from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.kill_chain_phase import KillChainPhase

T = TypeVar("T", bound="KillChainCoverage")


@_attrs_define
class KillChainCoverage:
    """Kill chain phase coverage summary.

    Attributes:
        phase (KillChainPhase):
        hypothesis_count (int):
        sigma_rule_count (int):
        active_hunt_count (int):
        covered (bool):
    """

    phase: KillChainPhase
    hypothesis_count: int
    sigma_rule_count: int
    active_hunt_count: int
    covered: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        phase = self.phase.value

        hypothesis_count = self.hypothesis_count

        sigma_rule_count = self.sigma_rule_count

        active_hunt_count = self.active_hunt_count

        covered = self.covered

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "phase": phase,
                "hypothesis_count": hypothesis_count,
                "sigma_rule_count": sigma_rule_count,
                "active_hunt_count": active_hunt_count,
                "covered": covered,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        phase = KillChainPhase(d.pop("phase"))

        hypothesis_count = d.pop("hypothesis_count")

        sigma_rule_count = d.pop("sigma_rule_count")

        active_hunt_count = d.pop("active_hunt_count")

        covered = d.pop("covered")

        kill_chain_coverage = cls(
            phase=phase,
            hypothesis_count=hypothesis_count,
            sigma_rule_count=sigma_rule_count,
            active_hunt_count=active_hunt_count,
            covered=covered,
        )

        kill_chain_coverage.additional_properties = d
        return kill_chain_coverage

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
