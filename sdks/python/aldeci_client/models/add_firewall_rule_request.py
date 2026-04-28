from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.add_firewall_rule_request_metadata import AddFirewallRuleRequestMetadata


T = TypeVar("T", bound="AddFirewallRuleRequest")


@_attrs_define
class AddFirewallRuleRequest:
    """
    Attributes:
        rule_name (str): Descriptive rule name
        src (str): Source CIDR or 'any'
        dst (str): Destination CIDR or 'any'
        port (str): Port number, range, or 'any'
        protocol (str | Unset): Protocol: tcp, udp, or any Default: 'tcp'.
        action (str | Unset): allow or deny Default: 'allow'.
        org_id (str | Unset):  Default: 'default'.
        bidirectional (bool | Unset):  Default: False.
        expiry (datetime.datetime | None | Unset): Optional expiry timestamp for temporary rules
        metadata (AddFirewallRuleRequestMetadata | Unset):
    """

    rule_name: str
    src: str
    dst: str
    port: str
    protocol: str | Unset = "tcp"
    action: str | Unset = "allow"
    org_id: str | Unset = "default"
    bidirectional: bool | Unset = False
    expiry: datetime.datetime | None | Unset = UNSET
    metadata: AddFirewallRuleRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_name = self.rule_name

        src = self.src

        dst = self.dst

        port = self.port

        protocol = self.protocol

        action = self.action

        org_id = self.org_id

        bidirectional = self.bidirectional

        expiry: None | str | Unset
        if isinstance(self.expiry, Unset):
            expiry = UNSET
        elif isinstance(self.expiry, datetime.datetime):
            expiry = self.expiry.isoformat()
        else:
            expiry = self.expiry

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_name": rule_name,
                "src": src,
                "dst": dst,
                "port": port,
            }
        )
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if action is not UNSET:
            field_dict["action"] = action
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if bidirectional is not UNSET:
            field_dict["bidirectional"] = bidirectional
        if expiry is not UNSET:
            field_dict["expiry"] = expiry
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_firewall_rule_request_metadata import AddFirewallRuleRequestMetadata

        d = dict(src_dict)
        rule_name = d.pop("rule_name")

        src = d.pop("src")

        dst = d.pop("dst")

        port = d.pop("port")

        protocol = d.pop("protocol", UNSET)

        action = d.pop("action", UNSET)

        org_id = d.pop("org_id", UNSET)

        bidirectional = d.pop("bidirectional", UNSET)

        def _parse_expiry(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                expiry_type_0 = isoparse(data)

                return expiry_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        expiry = _parse_expiry(d.pop("expiry", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: AddFirewallRuleRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AddFirewallRuleRequestMetadata.from_dict(_metadata)

        add_firewall_rule_request = cls(
            rule_name=rule_name,
            src=src,
            dst=dst,
            port=port,
            protocol=protocol,
            action=action,
            org_id=org_id,
            bidirectional=bidirectional,
            expiry=expiry,
            metadata=metadata,
        )

        add_firewall_rule_request.additional_properties = d
        return add_firewall_rule_request

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
