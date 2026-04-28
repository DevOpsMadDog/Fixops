from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SimulationRequest")


@_attrs_define
class SimulationRequest:
    """Request for attack path simulation.

    Attributes:
        start_state (str | Unset): Starting security state Default: 'Initial'.
        max_steps (int | Unset): Maximum simulation steps Default: 20.
        seed (int | None | Unset): Random seed for reproducibility
    """

    start_state: str | Unset = "Initial"
    max_steps: int | Unset = 20
    seed: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        start_state = self.start_state

        max_steps = self.max_steps

        seed: int | None | Unset
        if isinstance(self.seed, Unset):
            seed = UNSET
        else:
            seed = self.seed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if start_state is not UNSET:
            field_dict["start_state"] = start_state
        if max_steps is not UNSET:
            field_dict["max_steps"] = max_steps
        if seed is not UNSET:
            field_dict["seed"] = seed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        start_state = d.pop("start_state", UNSET)

        max_steps = d.pop("max_steps", UNSET)

        def _parse_seed(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        seed = _parse_seed(d.pop("seed", UNSET))

        simulation_request = cls(
            start_state=start_state,
            max_steps=max_steps,
            seed=seed,
        )

        simulation_request.additional_properties = d
        return simulation_request

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
