from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="UnifiedRuleCreate")


@_attrs_define
class UnifiedRuleCreate:
    """
    Attributes:
        rule_key (str): Canonical cross-engine key, e.g. 'sast.sql.injection'
        domain (str): sast/dast/secrets/iac/container/cspm/api_security/...
        category (str): Subcategory within domain
        severity (str): critical/high/medium/low/info
        rule_type (str): detection/validation/compliance/posture/hardening
        source_engine (str): Originating engine (e.g. sast_engine, secrets_scanner)
    """

    rule_key: str
    domain: str
    category: str
    severity: str
    rule_type: str
    source_engine: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_key = self.rule_key

        domain = self.domain

        category = self.category

        severity = self.severity

        rule_type = self.rule_type

        source_engine = self.source_engine

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_key": rule_key,
                "domain": domain,
                "category": category,
                "severity": severity,
                "rule_type": rule_type,
                "source_engine": source_engine,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_key = d.pop("rule_key")

        domain = d.pop("domain")

        category = d.pop("category")

        severity = d.pop("severity")

        rule_type = d.pop("rule_type")

        source_engine = d.pop("source_engine")

        unified_rule_create = cls(
            rule_key=rule_key,
            domain=domain,
            category=category,
            severity=severity,
            rule_type=rule_type,
            source_engine=source_engine,
        )

        unified_rule_create.additional_properties = d
        return unified_rule_create

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
