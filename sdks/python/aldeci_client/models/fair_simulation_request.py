from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FAIRSimulationRequest")


@_attrs_define
class FAIRSimulationRequest:
    """Full FAIR model simulation request.

    Attributes:
        tef_min (float | Unset): Min threat event frequency (per year) Default: 0.1.
        tef_max (float | Unset): Max threat event frequency Default: 10.0.
        tef_mode (float | Unset): Most likely threat event frequency Default: 2.0.
        vuln_min (float | Unset): Min vulnerability probability Default: 0.1.
        vuln_max (float | Unset): Max vulnerability probability Default: 0.9.
        vuln_mode (float | Unset): Most likely vulnerability probability Default: 0.5.
        primary_loss_min (float | Unset): Min primary loss ($) Default: 10000.0.
        primary_loss_max (float | Unset): Max primary loss ($) Default: 1000000.0.
        primary_loss_mode (float | Unset): Most likely primary loss ($) Default: 100000.0.
        secondary_loss_min (float | Unset): Min secondary loss ($) Default: 50000.0.
        secondary_loss_max (float | Unset): Max secondary loss ($) Default: 5000000.0.
        secondary_loss_mode (float | Unset): Most likely secondary loss ($) Default: 500000.0.
        slef_probability (float | Unset): Secondary loss event probability Default: 0.3.
        asset_value (float | Unset): Asset value ($) Default: 1000000.0.
        iterations (int | Unset): Monte Carlo iterations Default: 10000.
    """

    tef_min: float | Unset = 0.1
    tef_max: float | Unset = 10.0
    tef_mode: float | Unset = 2.0
    vuln_min: float | Unset = 0.1
    vuln_max: float | Unset = 0.9
    vuln_mode: float | Unset = 0.5
    primary_loss_min: float | Unset = 10000.0
    primary_loss_max: float | Unset = 1000000.0
    primary_loss_mode: float | Unset = 100000.0
    secondary_loss_min: float | Unset = 50000.0
    secondary_loss_max: float | Unset = 5000000.0
    secondary_loss_mode: float | Unset = 500000.0
    slef_probability: float | Unset = 0.3
    asset_value: float | Unset = 1000000.0
    iterations: int | Unset = 10000
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tef_min = self.tef_min

        tef_max = self.tef_max

        tef_mode = self.tef_mode

        vuln_min = self.vuln_min

        vuln_max = self.vuln_max

        vuln_mode = self.vuln_mode

        primary_loss_min = self.primary_loss_min

        primary_loss_max = self.primary_loss_max

        primary_loss_mode = self.primary_loss_mode

        secondary_loss_min = self.secondary_loss_min

        secondary_loss_max = self.secondary_loss_max

        secondary_loss_mode = self.secondary_loss_mode

        slef_probability = self.slef_probability

        asset_value = self.asset_value

        iterations = self.iterations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if tef_min is not UNSET:
            field_dict["tef_min"] = tef_min
        if tef_max is not UNSET:
            field_dict["tef_max"] = tef_max
        if tef_mode is not UNSET:
            field_dict["tef_mode"] = tef_mode
        if vuln_min is not UNSET:
            field_dict["vuln_min"] = vuln_min
        if vuln_max is not UNSET:
            field_dict["vuln_max"] = vuln_max
        if vuln_mode is not UNSET:
            field_dict["vuln_mode"] = vuln_mode
        if primary_loss_min is not UNSET:
            field_dict["primary_loss_min"] = primary_loss_min
        if primary_loss_max is not UNSET:
            field_dict["primary_loss_max"] = primary_loss_max
        if primary_loss_mode is not UNSET:
            field_dict["primary_loss_mode"] = primary_loss_mode
        if secondary_loss_min is not UNSET:
            field_dict["secondary_loss_min"] = secondary_loss_min
        if secondary_loss_max is not UNSET:
            field_dict["secondary_loss_max"] = secondary_loss_max
        if secondary_loss_mode is not UNSET:
            field_dict["secondary_loss_mode"] = secondary_loss_mode
        if slef_probability is not UNSET:
            field_dict["slef_probability"] = slef_probability
        if asset_value is not UNSET:
            field_dict["asset_value"] = asset_value
        if iterations is not UNSET:
            field_dict["iterations"] = iterations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tef_min = d.pop("tef_min", UNSET)

        tef_max = d.pop("tef_max", UNSET)

        tef_mode = d.pop("tef_mode", UNSET)

        vuln_min = d.pop("vuln_min", UNSET)

        vuln_max = d.pop("vuln_max", UNSET)

        vuln_mode = d.pop("vuln_mode", UNSET)

        primary_loss_min = d.pop("primary_loss_min", UNSET)

        primary_loss_max = d.pop("primary_loss_max", UNSET)

        primary_loss_mode = d.pop("primary_loss_mode", UNSET)

        secondary_loss_min = d.pop("secondary_loss_min", UNSET)

        secondary_loss_max = d.pop("secondary_loss_max", UNSET)

        secondary_loss_mode = d.pop("secondary_loss_mode", UNSET)

        slef_probability = d.pop("slef_probability", UNSET)

        asset_value = d.pop("asset_value", UNSET)

        iterations = d.pop("iterations", UNSET)

        fair_simulation_request = cls(
            tef_min=tef_min,
            tef_max=tef_max,
            tef_mode=tef_mode,
            vuln_min=vuln_min,
            vuln_max=vuln_max,
            vuln_mode=vuln_mode,
            primary_loss_min=primary_loss_min,
            primary_loss_max=primary_loss_max,
            primary_loss_mode=primary_loss_mode,
            secondary_loss_min=secondary_loss_min,
            secondary_loss_max=secondary_loss_max,
            secondary_loss_mode=secondary_loss_mode,
            slef_probability=slef_probability,
            asset_value=asset_value,
            iterations=iterations,
        )

        fair_simulation_request.additional_properties = d
        return fair_simulation_request

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
