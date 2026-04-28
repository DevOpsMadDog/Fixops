from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.threat_category import ThreatCategory
from ..models.threat_severity import ThreatSeverity
from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectionPattern")


@_attrs_define
class DetectionPattern:
    """A single detection rule.

    Attributes:
        rule_id (str):
        category (ThreatCategory): OWASP-aligned threat categories.
        name (str):
        description (str):
        pattern (str):
        severity (ThreatSeverity): Threat severity levels.
        confidence (float | Unset):  Default: 0.9.
        enabled (bool | Unset):  Default: True.
    """

    rule_id: str
    category: ThreatCategory
    name: str
    description: str
    pattern: str
    severity: ThreatSeverity
    confidence: float | Unset = 0.9
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_id = self.rule_id

        category = self.category.value

        name = self.name

        description = self.description

        pattern = self.pattern

        severity = self.severity.value

        confidence = self.confidence

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_id": rule_id,
                "category": category,
                "name": name,
                "description": description,
                "pattern": pattern,
                "severity": severity,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_id = d.pop("rule_id")

        category = ThreatCategory(d.pop("category"))

        name = d.pop("name")

        description = d.pop("description")

        pattern = d.pop("pattern")

        severity = ThreatSeverity(d.pop("severity"))

        confidence = d.pop("confidence", UNSET)

        enabled = d.pop("enabled", UNSET)

        detection_pattern = cls(
            rule_id=rule_id,
            category=category,
            name=name,
            description=description,
            pattern=pattern,
            severity=severity,
            confidence=confidence,
            enabled=enabled,
        )

        detection_pattern.additional_properties = d
        return detection_pattern

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
