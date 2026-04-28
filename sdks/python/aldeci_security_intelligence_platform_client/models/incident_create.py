from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IncidentCreate")


@_attrs_define
class IncidentCreate:
    """
    Attributes:
        model_id (str):
        incident_type (str):
        severity (str | Unset):  Default: 'medium'.
        description (str | Unset):  Default: ''.
    """

    model_id: str
    incident_type: str
    severity: str | Unset = "medium"
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        model_id = self.model_id

        incident_type = self.incident_type

        severity = self.severity

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "model_id": model_id,
                "incident_type": incident_type,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        model_id = d.pop("model_id")

        incident_type = d.pop("incident_type")

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        incident_create = cls(
            model_id=model_id,
            incident_type=incident_type,
            severity=severity,
            description=description,
        )

        incident_create.additional_properties = d
        return incident_create

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
