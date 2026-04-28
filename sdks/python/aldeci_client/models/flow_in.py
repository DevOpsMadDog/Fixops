from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FlowIn")


@_attrs_define
class FlowIn:
    """
    Attributes:
        src_ip (str | Unset):  Default: ''.
        src_port (int | Unset):  Default: 0.
        dst_ip (str | Unset):  Default: ''.
        dst_port (int | Unset):  Default: 0.
        protocol (str | Unset):  Default: 'tcp'.
        bytes_sent (int | Unset):  Default: 0.
        bytes_received (int | Unset):  Default: 0.
        packets (int | Unset):  Default: 0.
        duration_ms (int | Unset):  Default: 0.
        direction (str | Unset):  Default: 'outbound'.
    """

    src_ip: str | Unset = ""
    src_port: int | Unset = 0
    dst_ip: str | Unset = ""
    dst_port: int | Unset = 0
    protocol: str | Unset = "tcp"
    bytes_sent: int | Unset = 0
    bytes_received: int | Unset = 0
    packets: int | Unset = 0
    duration_ms: int | Unset = 0
    direction: str | Unset = "outbound"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        src_ip = self.src_ip

        src_port = self.src_port

        dst_ip = self.dst_ip

        dst_port = self.dst_port

        protocol = self.protocol

        bytes_sent = self.bytes_sent

        bytes_received = self.bytes_received

        packets = self.packets

        duration_ms = self.duration_ms

        direction = self.direction

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if src_ip is not UNSET:
            field_dict["src_ip"] = src_ip
        if src_port is not UNSET:
            field_dict["src_port"] = src_port
        if dst_ip is not UNSET:
            field_dict["dst_ip"] = dst_ip
        if dst_port is not UNSET:
            field_dict["dst_port"] = dst_port
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if bytes_sent is not UNSET:
            field_dict["bytes_sent"] = bytes_sent
        if bytes_received is not UNSET:
            field_dict["bytes_received"] = bytes_received
        if packets is not UNSET:
            field_dict["packets"] = packets
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms
        if direction is not UNSET:
            field_dict["direction"] = direction

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        src_ip = d.pop("src_ip", UNSET)

        src_port = d.pop("src_port", UNSET)

        dst_ip = d.pop("dst_ip", UNSET)

        dst_port = d.pop("dst_port", UNSET)

        protocol = d.pop("protocol", UNSET)

        bytes_sent = d.pop("bytes_sent", UNSET)

        bytes_received = d.pop("bytes_received", UNSET)

        packets = d.pop("packets", UNSET)

        duration_ms = d.pop("duration_ms", UNSET)

        direction = d.pop("direction", UNSET)

        flow_in = cls(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            packets=packets,
            duration_ms=duration_ms,
            direction=direction,
        )

        flow_in.additional_properties = d
        return flow_in

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
