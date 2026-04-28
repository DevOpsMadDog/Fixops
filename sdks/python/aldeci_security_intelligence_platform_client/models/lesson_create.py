from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LessonCreate")


@_attrs_define
class LessonCreate:
    """
    Attributes:
        incident_id (str):
        title (str):
        lesson_type (str):
        severity (str):
        description (str | Unset):  Default: ''.
        identified_by (str | Unset):  Default: ''.
    """

    incident_id: str
    title: str
    lesson_type: str
    severity: str
    description: str | Unset = ""
    identified_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        incident_id = self.incident_id

        title = self.title

        lesson_type = self.lesson_type

        severity = self.severity

        description = self.description

        identified_by = self.identified_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "incident_id": incident_id,
                "title": title,
                "lesson_type": lesson_type,
                "severity": severity,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if identified_by is not UNSET:
            field_dict["identified_by"] = identified_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        incident_id = d.pop("incident_id")

        title = d.pop("title")

        lesson_type = d.pop("lesson_type")

        severity = d.pop("severity")

        description = d.pop("description", UNSET)

        identified_by = d.pop("identified_by", UNSET)

        lesson_create = cls(
            incident_id=incident_id,
            title=title,
            lesson_type=lesson_type,
            severity=severity,
            description=description,
            identified_by=identified_by,
        )

        lesson_create.additional_properties = d
        return lesson_create

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
