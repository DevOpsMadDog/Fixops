from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IngestFlowRequest")


@_attrs_define
class IngestFlowRequest:
    """
    Attributes:
        src_ip (str | Unset): Source IP address Default: ''.
        dst_ip (str | Unset): Destination IP address Default: ''.
        src_port (int | Unset):  Default: 0.
        dst_port (int | Unset):  Default: 0.
        protocol (str | Unset): Protocol (TCP/UDP/ICMP/DNS/HTTP/HTTPS/SSH/RDP) Default: 'TCP'.
        bytes_sent (int | Unset):  Default: 0.
        bytes_recv (int | Unset):  Default: 0.
        duration_ms (int | Unset):  Default: 0.
        flow_type (str | Unset): internal/external/lateral/exfiltration_suspect/c2_suspect Default: 'internal'.
        mitre_technique (str | Unset):  Default: ''.
        observed_at (None | str | Unset):
    """

    src_ip: str | Unset = ""
    dst_ip: str | Unset = ""
    src_port: int | Unset = 0
    dst_port: int | Unset = 0
    protocol: str | Unset = "TCP"
    bytes_sent: int | Unset = 0
    bytes_recv: int | Unset = 0
    duration_ms: int | Unset = 0
    flow_type: str | Unset = "internal"
    mitre_technique: str | Unset = ""
    observed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        src_ip = self.src_ip

        dst_ip = self.dst_ip

        src_port = self.src_port

        dst_port = self.dst_port

        protocol = self.protocol

        bytes_sent = self.bytes_sent

        bytes_recv = self.bytes_recv

        duration_ms = self.duration_ms

        flow_type = self.flow_type

        mitre_technique = self.mitre_technique

        observed_at: None | str | Unset
        if isinstance(self.observed_at, Unset):
            observed_at = UNSET
        else:
            observed_at = self.observed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if src_ip is not UNSET:
            field_dict["src_ip"] = src_ip
        if dst_ip is not UNSET:
            field_dict["dst_ip"] = dst_ip
        if src_port is not UNSET:
            field_dict["src_port"] = src_port
        if dst_port is not UNSET:
            field_dict["dst_port"] = dst_port
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if bytes_sent is not UNSET:
            field_dict["bytes_sent"] = bytes_sent
        if bytes_recv is not UNSET:
            field_dict["bytes_recv"] = bytes_recv
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms
        if flow_type is not UNSET:
            field_dict["flow_type"] = flow_type
        if mitre_technique is not UNSET:
            field_dict["mitre_technique"] = mitre_technique
        if observed_at is not UNSET:
            field_dict["observed_at"] = observed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        src_ip = d.pop("src_ip", UNSET)

        dst_ip = d.pop("dst_ip", UNSET)

        src_port = d.pop("src_port", UNSET)

        dst_port = d.pop("dst_port", UNSET)

        protocol = d.pop("protocol", UNSET)

        bytes_sent = d.pop("bytes_sent", UNSET)

        bytes_recv = d.pop("bytes_recv", UNSET)

        duration_ms = d.pop("duration_ms", UNSET)

        flow_type = d.pop("flow_type", UNSET)

        mitre_technique = d.pop("mitre_technique", UNSET)

        def _parse_observed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        observed_at = _parse_observed_at(d.pop("observed_at", UNSET))

        ingest_flow_request = cls(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            duration_ms=duration_ms,
            flow_type=flow_type,
            mitre_technique=mitre_technique,
            observed_at=observed_at,
        )

        ingest_flow_request.additional_properties = d
        return ingest_flow_request

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
