from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="StartMonitorRequest")


@_attrs_define
class StartMonitorRequest:
    """
    Attributes:
        target (str | Unset): Hostname or IP to monitor Default: '127.0.0.1'.
        interval_seconds (int | Unset): Scan interval in seconds Default: 300.
        port_timeout (float | Unset): Per-port socket timeout in seconds Default: 0.1.
    """

    target: str | Unset = "127.0.0.1"
    interval_seconds: int | Unset = 300
    port_timeout: float | Unset = 0.1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target = self.target

        interval_seconds = self.interval_seconds

        port_timeout = self.port_timeout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if target is not UNSET:
            field_dict["target"] = target
        if interval_seconds is not UNSET:
            field_dict["interval_seconds"] = interval_seconds
        if port_timeout is not UNSET:
            field_dict["port_timeout"] = port_timeout

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target = d.pop("target", UNSET)

        interval_seconds = d.pop("interval_seconds", UNSET)

        port_timeout = d.pop("port_timeout", UNSET)

        start_monitor_request = cls(
            target=target,
            interval_seconds=interval_seconds,
            port_timeout=port_timeout,
        )

        start_monitor_request.additional_properties = d
        return start_monitor_request

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
