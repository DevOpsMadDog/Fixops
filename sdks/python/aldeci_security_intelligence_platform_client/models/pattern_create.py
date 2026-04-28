from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PatternCreate")


@_attrs_define
class PatternCreate:
    """
    Attributes:
        pattern_name (str):
        regex_pattern (str):
        secret_type (str | Unset):  Default: 'generic_api_key'.
        severity (str | Unset):  Default: 'medium'.
        enabled (bool | Unset):  Default: True.
        false_positive_rate (float | Unset):  Default: 0.0.
    """

    pattern_name: str
    regex_pattern: str
    secret_type: str | Unset = "generic_api_key"
    severity: str | Unset = "medium"
    enabled: bool | Unset = True
    false_positive_rate: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        pattern_name = self.pattern_name

        regex_pattern = self.regex_pattern

        secret_type = self.secret_type

        severity = self.severity

        enabled = self.enabled

        false_positive_rate = self.false_positive_rate

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "pattern_name": pattern_name,
                "regex_pattern": regex_pattern,
            }
        )
        if secret_type is not UNSET:
            field_dict["secret_type"] = secret_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if false_positive_rate is not UNSET:
            field_dict["false_positive_rate"] = false_positive_rate

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        pattern_name = d.pop("pattern_name")

        regex_pattern = d.pop("regex_pattern")

        secret_type = d.pop("secret_type", UNSET)

        severity = d.pop("severity", UNSET)

        enabled = d.pop("enabled", UNSET)

        false_positive_rate = d.pop("false_positive_rate", UNSET)

        pattern_create = cls(
            pattern_name=pattern_name,
            regex_pattern=regex_pattern,
            secret_type=secret_type,
            severity=severity,
            enabled=enabled,
            false_positive_rate=false_positive_rate,
        )

        pattern_create.additional_properties = d
        return pattern_create

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
