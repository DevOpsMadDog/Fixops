from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EmergingThreatCreate")


@_attrs_define
class EmergingThreatCreate:
    """
    Attributes:
        threat_name (str):
        threat_category (str | Unset):  Default: 'malware'.
        severity (str | Unset):  Default: 'medium'.
        description (str | Unset):  Default: ''.
        affected_sectors (list[str] | Unset):
        indicators (list[str] | Unset):
        mitigations (list[str] | Unset):
    """

    threat_name: str
    threat_category: str | Unset = "malware"
    severity: str | Unset = "medium"
    description: str | Unset = ""
    affected_sectors: list[str] | Unset = UNSET
    indicators: list[str] | Unset = UNSET
    mitigations: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_name = self.threat_name

        threat_category = self.threat_category

        severity = self.severity

        description = self.description

        affected_sectors: list[str] | Unset = UNSET
        if not isinstance(self.affected_sectors, Unset):
            affected_sectors = self.affected_sectors

        indicators: list[str] | Unset = UNSET
        if not isinstance(self.indicators, Unset):
            indicators = self.indicators

        mitigations: list[str] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = self.mitigations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "threat_name": threat_name,
            }
        )
        if threat_category is not UNSET:
            field_dict["threat_category"] = threat_category
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if affected_sectors is not UNSET:
            field_dict["affected_sectors"] = affected_sectors
        if indicators is not UNSET:
            field_dict["indicators"] = indicators
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        threat_name = d.pop("threat_name")

        threat_category = d.pop("threat_category", UNSET)

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        affected_sectors = cast(list[str], d.pop("affected_sectors", UNSET))

        indicators = cast(list[str], d.pop("indicators", UNSET))

        mitigations = cast(list[str], d.pop("mitigations", UNSET))

        emerging_threat_create = cls(
            threat_name=threat_name,
            threat_category=threat_category,
            severity=severity,
            description=description,
            affected_sectors=affected_sectors,
            indicators=indicators,
            mitigations=mitigations,
        )

        emerging_threat_create.additional_properties = d
        return emerging_threat_create

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
