from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ShadowITRequest")


@_attrs_define
class ShadowITRequest:
    """
    Attributes:
        network_range (str | Unset): Host to scan for shadow IT Default: '127.0.0.1'.
        port_timeout (float | Unset): Per-port socket timeout in seconds Default: 0.1.
    """

    network_range: str | Unset = "127.0.0.1"
    port_timeout: float | Unset = 0.1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        network_range = self.network_range

        port_timeout = self.port_timeout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if network_range is not UNSET:
            field_dict["network_range"] = network_range
        if port_timeout is not UNSET:
            field_dict["port_timeout"] = port_timeout

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        network_range = d.pop("network_range", UNSET)

        port_timeout = d.pop("port_timeout", UNSET)

        shadow_it_request = cls(
            network_range=network_range,
            port_timeout=port_timeout,
        )

        shadow_it_request.additional_properties = d
        return shadow_it_request

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
