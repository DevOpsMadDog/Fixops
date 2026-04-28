from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddTechniqueRequest")


@_attrs_define
class AddTechniqueRequest:
    """
    Attributes:
        technique_id (str): e.g. T1190
        name (str):
        tactic_id (str): e.g. TA0001
        description (str | Unset):  Default: ''.
        severity (str | Unset): critical|high|medium|low Default: 'medium'.
    """

    technique_id: str
    name: str
    tactic_id: str
    description: str | Unset = ""
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        technique_id = self.technique_id

        name = self.name

        tactic_id = self.tactic_id

        description = self.description

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
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
        technique_id = d.pop("technique_id")

        name = d.pop("name")

        tactic_id = d.pop("tactic_id")

        description = d.pop("description", UNSET)

        severity = d.pop("severity", UNSET)

        add_technique_request = cls(
            technique_id=technique_id,
            name=name,
            tactic_id=tactic_id,
            description=description,
            severity=severity,
        )

        add_technique_request.additional_properties = d
        return add_technique_request

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
