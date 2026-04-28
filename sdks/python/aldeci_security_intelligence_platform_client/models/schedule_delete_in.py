from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScheduleDeleteIn")


@_attrs_define
class ScheduleDeleteIn:
    """
    Attributes:
        scheduled_by (str | Unset):  Default: ''.
        notes (str | Unset):  Default: ''.
    """

    scheduled_by: str | Unset = ""
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scheduled_by = self.scheduled_by

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if scheduled_by is not UNSET:
            field_dict["scheduled_by"] = scheduled_by
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scheduled_by = d.pop("scheduled_by", UNSET)

        notes = d.pop("notes", UNSET)

        schedule_delete_in = cls(
            scheduled_by=scheduled_by,
            notes=notes,
        )

        schedule_delete_in.additional_properties = d
        return schedule_delete_in

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
