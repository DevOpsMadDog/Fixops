from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordResolutionRequest")


@_attrs_define
class RecordResolutionRequest:
    """
    Attributes:
        domain (str): Domain name (e.g. example.com)
        resolved_ip (str): IP address the domain resolved to
        org_id (str | Unset): Organisation ID Default: 'default'.
        record_type (str | Unset): DNS record type: A/AAAA/MX/NS/CNAME/TXT Default: 'A'.
        ttl (int | Unset): Time-to-live in seconds Default: 3600.
        first_seen (None | str | Unset): ISO8601 first seen timestamp
        last_seen (None | str | Unset): ISO8601 last seen timestamp
        source (str | Unset): Data source: sensor/feed/query Default: 'query'.
    """

    domain: str
    resolved_ip: str
    org_id: str | Unset = "default"
    record_type: str | Unset = "A"
    ttl: int | Unset = 3600
    first_seen: None | str | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    source: str | Unset = "query"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        resolved_ip = self.resolved_ip

        org_id = self.org_id

        record_type = self.record_type

        ttl = self.ttl

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain": domain,
                "resolved_ip": resolved_ip,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if record_type is not UNSET:
            field_dict["record_type"] = record_type
        if ttl is not UNSET:
            field_dict["ttl"] = ttl
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        resolved_ip = d.pop("resolved_ip")

        org_id = d.pop("org_id", UNSET)

        record_type = d.pop("record_type", UNSET)

        ttl = d.pop("ttl", UNSET)

        def _parse_first_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        source = d.pop("source", UNSET)

        record_resolution_request = cls(
            domain=domain,
            resolved_ip=resolved_ip,
            org_id=org_id,
            record_type=record_type,
            ttl=ttl,
            first_seen=first_seen,
            last_seen=last_seen,
            source=source,
        )

        record_resolution_request.additional_properties = d
        return record_resolution_request

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
