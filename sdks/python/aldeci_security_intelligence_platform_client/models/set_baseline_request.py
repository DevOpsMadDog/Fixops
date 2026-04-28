from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SetBaselineRequest")


@_attrs_define
class SetBaselineRequest:
    """
    Attributes:
        typical_protocols (list[str] | Unset):
        typical_ports (list[int] | Unset):
        typical_daily_bytes (int | Unset):  Default: 0.
        typical_connections_per_hr (int | Unset):  Default: 0.
    """

    typical_protocols: list[str] | Unset = UNSET
    typical_ports: list[int] | Unset = UNSET
    typical_daily_bytes: int | Unset = 0
    typical_connections_per_hr: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        typical_protocols: list[str] | Unset = UNSET
        if not isinstance(self.typical_protocols, Unset):
            typical_protocols = self.typical_protocols

        typical_ports: list[int] | Unset = UNSET
        if not isinstance(self.typical_ports, Unset):
            typical_ports = self.typical_ports

        typical_daily_bytes = self.typical_daily_bytes

        typical_connections_per_hr = self.typical_connections_per_hr

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if typical_protocols is not UNSET:
            field_dict["typical_protocols"] = typical_protocols
        if typical_ports is not UNSET:
            field_dict["typical_ports"] = typical_ports
        if typical_daily_bytes is not UNSET:
            field_dict["typical_daily_bytes"] = typical_daily_bytes
        if typical_connections_per_hr is not UNSET:
            field_dict["typical_connections_per_hr"] = typical_connections_per_hr

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        typical_protocols = cast(list[str], d.pop("typical_protocols", UNSET))

        typical_ports = cast(list[int], d.pop("typical_ports", UNSET))

        typical_daily_bytes = d.pop("typical_daily_bytes", UNSET)

        typical_connections_per_hr = d.pop("typical_connections_per_hr", UNSET)

        set_baseline_request = cls(
            typical_protocols=typical_protocols,
            typical_ports=typical_ports,
            typical_daily_bytes=typical_daily_bytes,
            typical_connections_per_hr=typical_connections_per_hr,
        )

        set_baseline_request.additional_properties = d
        return set_baseline_request

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
