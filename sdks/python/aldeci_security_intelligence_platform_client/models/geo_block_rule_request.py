from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GeoBlockRuleRequest")


@_attrs_define
class GeoBlockRuleRequest:
    """
    Attributes:
        country_code (str): ISO 3166-1 alpha-2 country code to block
        org_id (str | Unset):  Default: 'default'.
        reason (str | Unset): Reason for blocking Default: ''.
        severity (str | Unset): Severity: low, medium, high, critical Default: 'high'.
    """

    country_code: str
    org_id: str | Unset = "default"
    reason: str | Unset = ""
    severity: str | Unset = "high"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        country_code = self.country_code

        org_id = self.org_id

        reason = self.reason

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "country_code": country_code,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if reason is not UNSET:
            field_dict["reason"] = reason
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        country_code = d.pop("country_code")

        org_id = d.pop("org_id", UNSET)

        reason = d.pop("reason", UNSET)

        severity = d.pop("severity", UNSET)

        geo_block_rule_request = cls(
            country_code=country_code,
            org_id=org_id,
            reason=reason,
            severity=severity,
        )

        geo_block_rule_request.additional_properties = d
        return geo_block_rule_request

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
