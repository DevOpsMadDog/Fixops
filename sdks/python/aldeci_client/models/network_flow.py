from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="NetworkFlow")


@_attrs_define
class NetworkFlow:
    """
    Attributes:
        org_id (str):
        src_ip (str):
        dst_ip (str):
        src_port (int):
        dst_port (int):
        protocol (str):
        id (str | Unset):
        bytes_sent (int | Unset):  Default: 0.
        bytes_recv (int | Unset):  Default: 0.
        packet_count (int | Unset):  Default: 0.
        duration_ms (int | Unset):  Default: 0.
        observed_at (datetime.datetime | Unset):
    """

    org_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    id: str | Unset = UNSET
    bytes_sent: int | Unset = 0
    bytes_recv: int | Unset = 0
    packet_count: int | Unset = 0
    duration_ms: int | Unset = 0
    observed_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        src_ip = self.src_ip

        dst_ip = self.dst_ip

        src_port = self.src_port

        dst_port = self.dst_port

        protocol = self.protocol

        id = self.id

        bytes_sent = self.bytes_sent

        bytes_recv = self.bytes_recv

        packet_count = self.packet_count

        duration_ms = self.duration_ms

        observed_at: str | Unset = UNSET
        if not isinstance(self.observed_at, Unset):
            observed_at = self.observed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if bytes_sent is not UNSET:
            field_dict["bytes_sent"] = bytes_sent
        if bytes_recv is not UNSET:
            field_dict["bytes_recv"] = bytes_recv
        if packet_count is not UNSET:
            field_dict["packet_count"] = packet_count
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms
        if observed_at is not UNSET:
            field_dict["observed_at"] = observed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        src_ip = d.pop("src_ip")

        dst_ip = d.pop("dst_ip")

        src_port = d.pop("src_port")

        dst_port = d.pop("dst_port")

        protocol = d.pop("protocol")

        id = d.pop("id", UNSET)

        bytes_sent = d.pop("bytes_sent", UNSET)

        bytes_recv = d.pop("bytes_recv", UNSET)

        packet_count = d.pop("packet_count", UNSET)

        duration_ms = d.pop("duration_ms", UNSET)

        _observed_at = d.pop("observed_at", UNSET)
        observed_at: datetime.datetime | Unset
        if isinstance(_observed_at, Unset):
            observed_at = UNSET
        else:
            observed_at = isoparse(_observed_at)

        network_flow = cls(
            org_id=org_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            id=id,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            packet_count=packet_count,
            duration_ms=duration_ms,
            observed_at=observed_at,
        )

        network_flow.additional_properties = d
        return network_flow

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
