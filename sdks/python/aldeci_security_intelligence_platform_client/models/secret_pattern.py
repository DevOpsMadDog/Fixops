from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.secret_type import SecretType
from ..types import UNSET, Unset

T = TypeVar("T", bound="SecretPattern")


@_attrs_define
class SecretPattern:
    """A single secret detection pattern.

    Attributes:
        type_ (SecretType):
        pattern (str): Regex pattern string
        description (str):
        severity (str | Unset): critical | high | medium | low Default: 'high'.
        false_positive_patterns (list[str] | Unset): Regex patterns that indicate a false positive match
    """

    type_: SecretType
    pattern: str
    description: str
    severity: str | Unset = "high"
    false_positive_patterns: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        pattern = self.pattern

        description = self.description

        severity = self.severity

        false_positive_patterns: list[str] | Unset = UNSET
        if not isinstance(self.false_positive_patterns, Unset):
            false_positive_patterns = self.false_positive_patterns

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "pattern": pattern,
                "description": description,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if false_positive_patterns is not UNSET:
            field_dict["false_positive_patterns"] = false_positive_patterns

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = SecretType(d.pop("type"))

        pattern = d.pop("pattern")

        description = d.pop("description")

        severity = d.pop("severity", UNSET)

        false_positive_patterns = cast(list[str], d.pop("false_positive_patterns", UNSET))

        secret_pattern = cls(
            type_=type_,
            pattern=pattern,
            description=description,
            severity=severity,
            false_positive_patterns=false_positive_patterns,
        )

        secret_pattern.additional_properties = d
        return secret_pattern

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
