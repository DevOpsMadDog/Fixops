from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateHypothesisBody")


@_attrs_define
class CreateHypothesisBody:
    """
    Attributes:
        hypothesis (str): Hypothesis statement
        threat_category (str | Unset): lateral_movement | privilege_escalation | exfiltration | persistence |
            defense_evasion | discovery | collection | impact Default: 'lateral_movement'.
        mitre_technique (str | Unset): MITRE ATT&CK technique ID e.g. T1078 Default: ''.
        confidence (str | Unset): low | medium | high Default: 'medium'.
        data_sources (list[str] | Unset): List of data sources
        created_by (str | Unset): Creator user ID Default: ''.
    """

    hypothesis: str
    threat_category: str | Unset = "lateral_movement"
    mitre_technique: str | Unset = ""
    confidence: str | Unset = "medium"
    data_sources: list[str] | Unset = UNSET
    created_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hypothesis = self.hypothesis

        threat_category = self.threat_category

        mitre_technique = self.mitre_technique

        confidence = self.confidence

        data_sources: list[str] | Unset = UNSET
        if not isinstance(self.data_sources, Unset):
            data_sources = self.data_sources

        created_by = self.created_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hypothesis": hypothesis,
            }
        )
        if threat_category is not UNSET:
            field_dict["threat_category"] = threat_category
        if mitre_technique is not UNSET:
            field_dict["mitre_technique"] = mitre_technique
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if data_sources is not UNSET:
            field_dict["data_sources"] = data_sources
        if created_by is not UNSET:
            field_dict["created_by"] = created_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        hypothesis = d.pop("hypothesis")

        threat_category = d.pop("threat_category", UNSET)

        mitre_technique = d.pop("mitre_technique", UNSET)

        confidence = d.pop("confidence", UNSET)

        data_sources = cast(list[str], d.pop("data_sources", UNSET))

        created_by = d.pop("created_by", UNSET)

        create_hypothesis_body = cls(
            hypothesis=hypothesis,
            threat_category=threat_category,
            mitre_technique=mitre_technique,
            confidence=confidence,
            data_sources=data_sources,
            created_by=created_by,
        )

        create_hypothesis_body.additional_properties = d
        return create_hypothesis_body

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
