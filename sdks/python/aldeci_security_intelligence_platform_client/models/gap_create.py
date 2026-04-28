from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GapCreate")


@_attrs_define
class GapCreate:
    """
    Attributes:
        title (str):
        description (str | Unset):  Default: ''.
        gap_type (str | Unset):  Default: 'capability'.
        severity (str | Unset):  Default: 'medium'.
        linked_initiative_id (str | Unset):  Default: ''.
    """

    title: str
    description: str | Unset = ""
    gap_type: str | Unset = "capability"
    severity: str | Unset = "medium"
    linked_initiative_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        gap_type = self.gap_type

        severity = self.severity

        linked_initiative_id = self.linked_initiative_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if gap_type is not UNSET:
            field_dict["gap_type"] = gap_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if linked_initiative_id is not UNSET:
            field_dict["linked_initiative_id"] = linked_initiative_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description", UNSET)

        gap_type = d.pop("gap_type", UNSET)

        severity = d.pop("severity", UNSET)

        linked_initiative_id = d.pop("linked_initiative_id", UNSET)

        gap_create = cls(
            title=title,
            description=description,
            gap_type=gap_type,
            severity=severity,
            linked_initiative_id=linked_initiative_id,
        )

        gap_create.additional_properties = d
        return gap_create

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
