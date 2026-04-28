from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnalyseDNSRequest")


@_attrs_define
class AnalyseDNSRequest:
    """
    Attributes:
        domain (str): DNS domain to analyse
        resolver_ip (None | str | Unset): IP of the DNS resolver used
        query_size_bytes (int | Unset): Size of the DNS query payload in bytes Default: 0.
        org_id (str | Unset):  Default: 'default'.
    """

    domain: str
    resolver_ip: None | str | Unset = UNSET
    query_size_bytes: int | Unset = 0
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        resolver_ip: None | str | Unset
        if isinstance(self.resolver_ip, Unset):
            resolver_ip = UNSET
        else:
            resolver_ip = self.resolver_ip

        query_size_bytes = self.query_size_bytes

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain": domain,
            }
        )
        if resolver_ip is not UNSET:
            field_dict["resolver_ip"] = resolver_ip
        if query_size_bytes is not UNSET:
            field_dict["query_size_bytes"] = query_size_bytes
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        def _parse_resolver_ip(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        resolver_ip = _parse_resolver_ip(d.pop("resolver_ip", UNSET))

        query_size_bytes = d.pop("query_size_bytes", UNSET)

        org_id = d.pop("org_id", UNSET)

        analyse_dns_request = cls(
            domain=domain,
            resolver_ip=resolver_ip,
            query_size_bytes=query_size_bytes,
            org_id=org_id,
        )

        analyse_dns_request.additional_properties = d
        return analyse_dns_request

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
