from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RuleCreate")


@_attrs_define
class RuleCreate:
    """
    Attributes:
        rule_name (str | Unset):  Default: ''.
        src_zone (str | Unset):  Default: ''.
        dst_zone (str | Unset):  Default: ''.
        src_address (str | Unset):  Default: 'any'.
        dst_address (str | Unset):  Default: 'any'.
        service (list[str] | Unset):
        action (str | Unset):  Default: 'deny'.
        expires_at (None | str | Unset):
    """

    rule_name: str | Unset = ""
    src_zone: str | Unset = ""
    dst_zone: str | Unset = ""
    src_address: str | Unset = "any"
    dst_address: str | Unset = "any"
    service: list[str] | Unset = UNSET
    action: str | Unset = "deny"
    expires_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_name = self.rule_name

        src_zone = self.src_zone

        dst_zone = self.dst_zone

        src_address = self.src_address

        dst_address = self.dst_address

        service: list[str] | Unset = UNSET
        if not isinstance(self.service, Unset):
            service = self.service

        action = self.action

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if rule_name is not UNSET:
            field_dict["rule_name"] = rule_name
        if src_zone is not UNSET:
            field_dict["src_zone"] = src_zone
        if dst_zone is not UNSET:
            field_dict["dst_zone"] = dst_zone
        if src_address is not UNSET:
            field_dict["src_address"] = src_address
        if dst_address is not UNSET:
            field_dict["dst_address"] = dst_address
        if service is not UNSET:
            field_dict["service"] = service
        if action is not UNSET:
            field_dict["action"] = action
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_name = d.pop("rule_name", UNSET)

        src_zone = d.pop("src_zone", UNSET)

        dst_zone = d.pop("dst_zone", UNSET)

        src_address = d.pop("src_address", UNSET)

        dst_address = d.pop("dst_address", UNSET)

        service = cast(list[str], d.pop("service", UNSET))

        action = d.pop("action", UNSET)

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        rule_create = cls(
            rule_name=rule_name,
            src_zone=src_zone,
            dst_zone=dst_zone,
            src_address=src_address,
            dst_address=dst_address,
            service=service,
            action=action,
            expires_at=expires_at,
        )

        rule_create.additional_properties = d
        return rule_create

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
