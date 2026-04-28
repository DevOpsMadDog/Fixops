from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskTrajectoryRequest")


@_attrs_define
class RiskTrajectoryRequest:
    """Request for risk trajectory calculation.

    Attributes:
        current_state (str | Unset): Current security state Default: 'Initial'.
        horizon_steps (int | Unset): Number of steps to predict Default: 10.
    """

    current_state: str | Unset = "Initial"
    horizon_steps: int | Unset = 10
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        current_state = self.current_state

        horizon_steps = self.horizon_steps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if current_state is not UNSET:
            field_dict["current_state"] = current_state
        if horizon_steps is not UNSET:
            field_dict["horizon_steps"] = horizon_steps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        current_state = d.pop("current_state", UNSET)

        horizon_steps = d.pop("horizon_steps", UNSET)

        risk_trajectory_request = cls(
            current_state=current_state,
            horizon_steps=horizon_steps,
        )

        risk_trajectory_request.additional_properties = d
        return risk_trajectory_request

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
