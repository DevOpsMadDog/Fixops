from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddFirewallRequest")


@_attrs_define
class AddFirewallRequest:
    """
    Attributes:
        name (str): Friendly name for the firewall
        org_id (str | Unset): Organisation ID Default: 'default'.
        vendor (str | Unset): Vendor: palo_alto/cisco/fortinet/checkpoint/aws_sg/azure_nsg Default: 'unknown'.
        ip_address (str | Unset): Management IP address Default: ''.
        status (str | Unset): active or inactive Default: 'active'.
        rule_count (int | Unset): Known rule count (metadata only) Default: 0.
        last_audited (None | str | Unset): ISO-8601 timestamp of last audit
    """

    name: str
    org_id: str | Unset = "default"
    vendor: str | Unset = "unknown"
    ip_address: str | Unset = ""
    status: str | Unset = "active"
    rule_count: int | Unset = 0
    last_audited: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_id = self.org_id

        vendor = self.vendor

        ip_address = self.ip_address

        status = self.status

        rule_count = self.rule_count

        last_audited: None | str | Unset
        if isinstance(self.last_audited, Unset):
            last_audited = UNSET
        else:
            last_audited = self.last_audited

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if status is not UNSET:
            field_dict["status"] = status
        if rule_count is not UNSET:
            field_dict["rule_count"] = rule_count
        if last_audited is not UNSET:
            field_dict["last_audited"] = last_audited

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        org_id = d.pop("org_id", UNSET)

        vendor = d.pop("vendor", UNSET)

        ip_address = d.pop("ip_address", UNSET)

        status = d.pop("status", UNSET)

        rule_count = d.pop("rule_count", UNSET)

        def _parse_last_audited(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_audited = _parse_last_audited(d.pop("last_audited", UNSET))

        add_firewall_request = cls(
            name=name,
            org_id=org_id,
            vendor=vendor,
            ip_address=ip_address,
            status=status,
            rule_count=rule_count,
            last_audited=last_audited,
        )

        add_firewall_request.additional_properties = d
        return add_firewall_request

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
