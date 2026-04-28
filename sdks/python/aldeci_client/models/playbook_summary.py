from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="PlaybookSummary")


@_attrs_define
class PlaybookSummary:
    """Lightweight playbook summary for list responses.

    Attributes:
        id (str):
        name (str):
        incident_type (str):
        description (str):
        severity_threshold (str):
        phase_count (int):
        step_count (int):
        applicable_regulations (list[str]):
    """

    id: str
    name: str
    incident_type: str
    description: str
    severity_threshold: str
    phase_count: int
    step_count: int
    applicable_regulations: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        incident_type = self.incident_type

        description = self.description

        severity_threshold = self.severity_threshold

        phase_count = self.phase_count

        step_count = self.step_count

        applicable_regulations = self.applicable_regulations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "incident_type": incident_type,
                "description": description,
                "severity_threshold": severity_threshold,
                "phase_count": phase_count,
                "step_count": step_count,
                "applicable_regulations": applicable_regulations,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        incident_type = d.pop("incident_type")

        description = d.pop("description")

        severity_threshold = d.pop("severity_threshold")

        phase_count = d.pop("phase_count")

        step_count = d.pop("step_count")

        applicable_regulations = cast(list[str], d.pop("applicable_regulations"))

        playbook_summary = cls(
            id=id,
            name=name,
            incident_type=incident_type,
            description=description,
            severity_threshold=severity_threshold,
            phase_count=phase_count,
            step_count=step_count,
            applicable_regulations=applicable_regulations,
        )

        playbook_summary.additional_properties = d
        return playbook_summary

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
