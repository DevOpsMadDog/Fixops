from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SimulateAttackRequest")


@_attrs_define
class SimulateAttackRequest:
    """Request to simulate attack scenario.

    Attributes:
        target_assets (list[str]):
        scenario_type (str | Unset): ransomware, apt, insider Default: 'ransomware'.
        kill_chain_stages (list[str] | Unset):
    """

    target_assets: list[str]
    scenario_type: str | Unset = "ransomware"
    kill_chain_stages: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_assets = self.target_assets

        scenario_type = self.scenario_type

        kill_chain_stages: list[str] | Unset = UNSET
        if not isinstance(self.kill_chain_stages, Unset):
            kill_chain_stages = self.kill_chain_stages

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target_assets": target_assets,
            }
        )
        if scenario_type is not UNSET:
            field_dict["scenario_type"] = scenario_type
        if kill_chain_stages is not UNSET:
            field_dict["kill_chain_stages"] = kill_chain_stages

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target_assets = cast(list[str], d.pop("target_assets"))

        scenario_type = d.pop("scenario_type", UNSET)

        kill_chain_stages = cast(list[str], d.pop("kill_chain_stages", UNSET))

        simulate_attack_request = cls(
            target_assets=target_assets,
            scenario_type=scenario_type,
            kill_chain_stages=kill_chain_stages,
        )

        simulate_attack_request.additional_properties = d
        return simulate_attack_request

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
