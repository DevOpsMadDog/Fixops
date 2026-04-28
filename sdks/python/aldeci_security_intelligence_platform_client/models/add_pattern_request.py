from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddPatternRequest")


@_attrs_define
class AddPatternRequest:
    """
    Attributes:
        name (str): Unique pattern name
        pattern (str): Python regex pattern string
        severity (str): Severity: low | medium | high | critical
        category (str): Category label (e.g. pii, pci, credentials)
        org_id (str | Unset): Organisation identifier Default: 'default'.
    """

    name: str
    pattern: str
    severity: str
    category: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        pattern = self.pattern

        severity = self.severity

        category = self.category

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "pattern": pattern,
                "severity": severity,
                "category": category,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        pattern = d.pop("pattern")

        severity = d.pop("severity")

        category = d.pop("category")

        org_id = d.pop("org_id", UNSET)

        add_pattern_request = cls(
            name=name,
            pattern=pattern,
            severity=severity,
            category=category,
            org_id=org_id,
        )

        add_pattern_request.additional_properties = d
        return add_pattern_request

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
