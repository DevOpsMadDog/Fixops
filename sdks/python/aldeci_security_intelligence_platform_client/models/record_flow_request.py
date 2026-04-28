from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordFlowRequest")


@_attrs_define
class RecordFlowRequest:
    """
    Attributes:
        src_ip (str): Source IP address
        dst_ip (str): Destination IP address
        src_port (int): Source port
        dst_port (int): Destination port
        protocol (str | Unset): Protocol: tcp or udp Default: 'tcp'.
        bytes_sent (int | Unset): Bytes from source to destination Default: 0.
        bytes_recv (int | Unset): Bytes from destination to source Default: 0.
        packet_count (int | Unset):  Default: 0.
        duration_ms (int | Unset):  Default: 0.
        org_id (str | Unset):  Default: 'default'.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str | Unset = "tcp"
    bytes_sent: int | Unset = 0
    bytes_recv: int | Unset = 0
    packet_count: int | Unset = 0
    duration_ms: int | Unset = 0
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        src_ip = self.src_ip

        dst_ip = self.dst_ip

        src_port = self.src_port

        dst_port = self.dst_port

        protocol = self.protocol

        bytes_sent = self.bytes_sent

        bytes_recv = self.bytes_recv

        packet_count = self.packet_count

        duration_ms = self.duration_ms

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
            }
        )
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if bytes_sent is not UNSET:
            field_dict["bytes_sent"] = bytes_sent
        if bytes_recv is not UNSET:
            field_dict["bytes_recv"] = bytes_recv
        if packet_count is not UNSET:
            field_dict["packet_count"] = packet_count
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        src_ip = d.pop("src_ip")

        dst_ip = d.pop("dst_ip")

        src_port = d.pop("src_port")

        dst_port = d.pop("dst_port")

        protocol = d.pop("protocol", UNSET)

        bytes_sent = d.pop("bytes_sent", UNSET)

        bytes_recv = d.pop("bytes_recv", UNSET)

        packet_count = d.pop("packet_count", UNSET)

        duration_ms = d.pop("duration_ms", UNSET)

        org_id = d.pop("org_id", UNSET)

        record_flow_request = cls(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            packet_count=packet_count,
            duration_ms=duration_ms,
            org_id=org_id,
        )

        record_flow_request.additional_properties = d
        return record_flow_request

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
