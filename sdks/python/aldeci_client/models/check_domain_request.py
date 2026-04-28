from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CheckDomainRequest")


@_attrs_define
class CheckDomainRequest:
    """
    Attributes:
        domain (str): Domain to probe
        port (int | Unset): TLS port (default 443) Default: 443.
        timeout (int | Unset): Socket timeout in seconds Default: 5.
    """

    domain: str
    port: int | Unset = 443
    timeout: int | Unset = 5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        port = self.port

        timeout = self.timeout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain": domain,
            }
        )
        if port is not UNSET:
            field_dict["port"] = port
        if timeout is not UNSET:
            field_dict["timeout"] = timeout

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        port = d.pop("port", UNSET)

        timeout = d.pop("timeout", UNSET)

        check_domain_request = cls(
            domain=domain,
            port=port,
            timeout=timeout,
        )

        check_domain_request.additional_properties = d
        return check_domain_request

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
