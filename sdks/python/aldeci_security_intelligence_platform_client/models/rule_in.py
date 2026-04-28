from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RuleIn")


@_attrs_define
class RuleIn:
    """
    Attributes:
        rule_name (str):
        src_cidr (str | Unset):  Default: ''.
        dst_cidr (str | Unset):  Default: ''.
        port_range (str | Unset):  Default: ''.
        protocol (str | Unset):  Default: 'tcp'.
        action (str | Unset):  Default: 'monitor'.
        priority (int | Unset):  Default: 100.
        enabled (bool | Unset):  Default: True.
    """

    rule_name: str
    src_cidr: str | Unset = ""
    dst_cidr: str | Unset = ""
    port_range: str | Unset = ""
    protocol: str | Unset = "tcp"
    action: str | Unset = "monitor"
    priority: int | Unset = 100
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_name = self.rule_name

        src_cidr = self.src_cidr

        dst_cidr = self.dst_cidr

        port_range = self.port_range

        protocol = self.protocol

        action = self.action

        priority = self.priority

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_name": rule_name,
            }
        )
        if src_cidr is not UNSET:
            field_dict["src_cidr"] = src_cidr
        if dst_cidr is not UNSET:
            field_dict["dst_cidr"] = dst_cidr
        if port_range is not UNSET:
            field_dict["port_range"] = port_range
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if action is not UNSET:
            field_dict["action"] = action
        if priority is not UNSET:
            field_dict["priority"] = priority
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_name = d.pop("rule_name")

        src_cidr = d.pop("src_cidr", UNSET)

        dst_cidr = d.pop("dst_cidr", UNSET)

        port_range = d.pop("port_range", UNSET)

        protocol = d.pop("protocol", UNSET)

        action = d.pop("action", UNSET)

        priority = d.pop("priority", UNSET)

        enabled = d.pop("enabled", UNSET)

        rule_in = cls(
            rule_name=rule_name,
            src_cidr=src_cidr,
            dst_cidr=dst_cidr,
            port_range=port_range,
            protocol=protocol,
            action=action,
            priority=priority,
            enabled=enabled,
        )

        rule_in.additional_properties = d
        return rule_in

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
