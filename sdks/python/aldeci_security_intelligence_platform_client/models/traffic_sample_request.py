from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TrafficSampleRequest")


@_attrs_define
class TrafficSampleRequest:
    """
    Attributes:
        segment (str): Network segment name
        org_id (str | Unset): Organisation ID Default: 'default'.
        protocol (str | Unset): TCP/UDP/ICMP/HTTP/HTTPS/DNS/SMTP/FTP/SSH/other Default: 'TCP'.
        direction (str | Unset): inbound/outbound/lateral Default: 'inbound'.
        bytes_per_min (float | Unset): Bytes per minute Default: 0.0.
        packets_per_min (float | Unset): Packets per minute Default: 0.0.
    """

    segment: str
    org_id: str | Unset = "default"
    protocol: str | Unset = "TCP"
    direction: str | Unset = "inbound"
    bytes_per_min: float | Unset = 0.0
    packets_per_min: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        segment = self.segment

        org_id = self.org_id

        protocol = self.protocol

        direction = self.direction

        bytes_per_min = self.bytes_per_min

        packets_per_min = self.packets_per_min

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "segment": segment,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if direction is not UNSET:
            field_dict["direction"] = direction
        if bytes_per_min is not UNSET:
            field_dict["bytes_per_min"] = bytes_per_min
        if packets_per_min is not UNSET:
            field_dict["packets_per_min"] = packets_per_min

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        segment = d.pop("segment")

        org_id = d.pop("org_id", UNSET)

        protocol = d.pop("protocol", UNSET)

        direction = d.pop("direction", UNSET)

        bytes_per_min = d.pop("bytes_per_min", UNSET)

        packets_per_min = d.pop("packets_per_min", UNSET)

        traffic_sample_request = cls(
            segment=segment,
            org_id=org_id,
            protocol=protocol,
            direction=direction,
            bytes_per_min=bytes_per_min,
            packets_per_min=packets_per_min,
        )

        traffic_sample_request.additional_properties = d
        return traffic_sample_request

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
