from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IncidentReport")


@_attrs_define
class IncidentReport:
    """
    Attributes:
        incident_type (str | Unset):  Default: 'service_outage'.
        severity (str | Unset):  Default: 'medium'.
        description (str | Unset):  Default: ''.
        impact (str | Unset):  Default: ''.
    """

    incident_type: str | Unset = "service_outage"
    severity: str | Unset = "medium"
    description: str | Unset = ""
    impact: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        incident_type = self.incident_type

        severity = self.severity

        description = self.description

        impact = self.impact

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if incident_type is not UNSET:
            field_dict["incident_type"] = incident_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if impact is not UNSET:
            field_dict["impact"] = impact

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        incident_type = d.pop("incident_type", UNSET)

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        impact = d.pop("impact", UNSET)

        incident_report = cls(
            incident_type=incident_type,
            severity=severity,
            description=description,
            impact=impact,
        )

        incident_report.additional_properties = d
        return incident_report

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
