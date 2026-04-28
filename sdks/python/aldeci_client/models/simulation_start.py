from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SimulationStart")


@_attrs_define
class SimulationStart:
    """
    Attributes:
        scenario_id (str):
        initiated_by (str):
        target_systems (list[str] | Unset):
    """

    scenario_id: str
    initiated_by: str
    target_systems: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario_id = self.scenario_id

        initiated_by = self.initiated_by

        target_systems: list[str] | Unset = UNSET
        if not isinstance(self.target_systems, Unset):
            target_systems = self.target_systems

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario_id": scenario_id,
                "initiated_by": initiated_by,
            }
        )
        if target_systems is not UNSET:
            field_dict["target_systems"] = target_systems

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario_id = d.pop("scenario_id")

        initiated_by = d.pop("initiated_by")

        target_systems = cast(list[str], d.pop("target_systems", UNSET))

        simulation_start = cls(
            scenario_id=scenario_id,
            initiated_by=initiated_by,
            target_systems=target_systems,
        )

        simulation_start.additional_properties = d
        return simulation_start

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
