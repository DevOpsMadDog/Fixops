from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.firewall_rule_metadata import FirewallRuleMetadata


T = TypeVar("T", bound="FirewallRule")


@_attrs_define
class FirewallRule:
    """
    Attributes:
        org_id (str):
        rule_name (str):
        src (str):
        dst (str):
        port (str):
        protocol (str):
        action (str):
        id (str | Unset):
        bidirectional (bool | Unset):  Default: False.
        expiry (datetime.datetime | None | Unset):
        hit_count (int | Unset):  Default: 0.
        created_at (datetime.datetime | Unset):
        metadata (FirewallRuleMetadata | Unset):
    """

    org_id: str
    rule_name: str
    src: str
    dst: str
    port: str
    protocol: str
    action: str
    id: str | Unset = UNSET
    bidirectional: bool | Unset = False
    expiry: datetime.datetime | None | Unset = UNSET
    hit_count: int | Unset = 0
    created_at: datetime.datetime | Unset = UNSET
    metadata: FirewallRuleMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        rule_name = self.rule_name

        src = self.src

        dst = self.dst

        port = self.port

        protocol = self.protocol

        action = self.action

        id = self.id

        bidirectional = self.bidirectional

        expiry: None | str | Unset
        if isinstance(self.expiry, Unset):
            expiry = UNSET
        elif isinstance(self.expiry, datetime.datetime):
            expiry = self.expiry.isoformat()
        else:
            expiry = self.expiry

        hit_count = self.hit_count

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "rule_name": rule_name,
                "src": src,
                "dst": dst,
                "port": port,
                "protocol": protocol,
                "action": action,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if bidirectional is not UNSET:
            field_dict["bidirectional"] = bidirectional
        if expiry is not UNSET:
            field_dict["expiry"] = expiry
        if hit_count is not UNSET:
            field_dict["hit_count"] = hit_count
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.firewall_rule_metadata import FirewallRuleMetadata

        d = dict(src_dict)
        org_id = d.pop("org_id")

        rule_name = d.pop("rule_name")

        src = d.pop("src")

        dst = d.pop("dst")

        port = d.pop("port")

        protocol = d.pop("protocol")

        action = d.pop("action")

        id = d.pop("id", UNSET)

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

        hit_count = d.pop("hit_count", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        _metadata = d.pop("metadata", UNSET)
        metadata: FirewallRuleMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = FirewallRuleMetadata.from_dict(_metadata)

        firewall_rule = cls(
            org_id=org_id,
            rule_name=rule_name,
            src=src,
            dst=dst,
            port=port,
            protocol=protocol,
            action=action,
            id=id,
            bidirectional=bidirectional,
            expiry=expiry,
            hit_count=hit_count,
            created_at=created_at,
            metadata=metadata,
        )

        firewall_rule.additional_properties = d
        return firewall_rule

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
