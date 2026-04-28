from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RunbookCreate")


@_attrs_define
class RunbookCreate:
    """
    Attributes:
        runbook_name (str):
        incident_type (str):
        steps (Any | Unset):  Default: [].
        estimated_minutes (int | Unset):  Default: 30.
    """

    runbook_name: str
    incident_type: str
    steps: Any | Unset = []
    estimated_minutes: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        runbook_name = self.runbook_name

        incident_type = self.incident_type

        steps = self.steps

        estimated_minutes = self.estimated_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "runbook_name": runbook_name,
                "incident_type": incident_type,
            }
        )
        if steps is not UNSET:
            field_dict["steps"] = steps
        if estimated_minutes is not UNSET:
            field_dict["estimated_minutes"] = estimated_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        runbook_name = d.pop("runbook_name")

        incident_type = d.pop("incident_type")

        steps = d.pop("steps", UNSET)

        estimated_minutes = d.pop("estimated_minutes", UNSET)

        runbook_create = cls(
            runbook_name=runbook_name,
            incident_type=incident_type,
            steps=steps,
            estimated_minutes=estimated_minutes,
        )

        runbook_create.additional_properties = d
        return runbook_create

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
