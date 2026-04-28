from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReportDNSRebindingRequest")


@_attrs_define
class ReportDNSRebindingRequest:
    """
    Attributes:
        domain (str): Public domain that was resolved
        resolved_ip (str): IP address the domain resolved to
        org_id (str | Unset):  Default: 'default'.
    """

    domain: str
    resolved_ip: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        resolved_ip = self.resolved_ip

        org_id = self.org_id

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

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        resolved_ip = d.pop("resolved_ip")

        org_id = d.pop("org_id", UNSET)

        report_dns_rebinding_request = cls(
            domain=domain,
            resolved_ip=resolved_ip,
            org_id=org_id,
        )

        report_dns_rebinding_request.additional_properties = d
        return report_dns_rebinding_request

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
