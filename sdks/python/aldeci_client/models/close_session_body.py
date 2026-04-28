from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CloseSessionBody")


@_attrs_define
class CloseSessionBody:
    """
    Attributes:
        commands_executed (int | Unset): Number of commands run Default: 0.
        anomaly_score (float | Unset): Anomaly score 0.0-10.0 (clamped) Default: 0.0.
    """

    commands_executed: int | Unset = 0
    anomaly_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        commands_executed = self.commands_executed

        anomaly_score = self.anomaly_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if commands_executed is not UNSET:
            field_dict["commands_executed"] = commands_executed
        if anomaly_score is not UNSET:
            field_dict["anomaly_score"] = anomaly_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        commands_executed = d.pop("commands_executed", UNSET)

        anomaly_score = d.pop("anomaly_score", UNSET)

        close_session_body = cls(
            commands_executed=commands_executed,
            anomaly_score=anomaly_score,
        )

        close_session_body.additional_properties = d
        return close_session_body

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
