from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TechniqueRequest")


@_attrs_define
class TechniqueRequest:
    """
    Attributes:
        org_id (str):
        technique_id (str):
        name (str):
        tactic_id (str):
        description (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
    """

    org_id: str
    technique_id: str
    name: str
    tactic_id: str
    description: str | Unset = ""
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        technique_id = self.technique_id

        name = self.name

        tactic_id = self.tactic_id

        description = self.description

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "technique_id": technique_id,
                "name": name,
                "tactic_id": tactic_id,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        technique_id = d.pop("technique_id")

        name = d.pop("name")

        tactic_id = d.pop("tactic_id")

        description = d.pop("description", UNSET)

        severity = d.pop("severity", UNSET)

        technique_request = cls(
            org_id=org_id,
            technique_id=technique_id,
            name=name,
            tactic_id=tactic_id,
            description=description,
            severity=severity,
        )

        technique_request.additional_properties = d
        return technique_request

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
