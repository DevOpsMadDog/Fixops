from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SimulationComplete")


@_attrs_define
class SimulationComplete:
    """
    Attributes:
        total_techniques_executed (int | Unset):  Default: 0.
        techniques_detected (int | Unset):  Default: 0.
        dwell_time_seconds (int | None | Unset):
    """

    total_techniques_executed: int | Unset = 0
    techniques_detected: int | Unset = 0
    dwell_time_seconds: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_techniques_executed = self.total_techniques_executed

        techniques_detected = self.techniques_detected

        dwell_time_seconds: int | None | Unset
        if isinstance(self.dwell_time_seconds, Unset):
            dwell_time_seconds = UNSET
        else:
            dwell_time_seconds = self.dwell_time_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if total_techniques_executed is not UNSET:
            field_dict["total_techniques_executed"] = total_techniques_executed
        if techniques_detected is not UNSET:
            field_dict["techniques_detected"] = techniques_detected
        if dwell_time_seconds is not UNSET:
            field_dict["dwell_time_seconds"] = dwell_time_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        total_techniques_executed = d.pop("total_techniques_executed", UNSET)

        techniques_detected = d.pop("techniques_detected", UNSET)

        def _parse_dwell_time_seconds(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        dwell_time_seconds = _parse_dwell_time_seconds(d.pop("dwell_time_seconds", UNSET))

        simulation_complete = cls(
            total_techniques_executed=total_techniques_executed,
            techniques_detected=techniques_detected,
            dwell_time_seconds=dwell_time_seconds,
        )

        simulation_complete.additional_properties = d
        return simulation_complete

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
