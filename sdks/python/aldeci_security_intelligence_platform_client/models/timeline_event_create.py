from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TimelineEventCreate")


@_attrs_define
class TimelineEventCreate:
    """
    Attributes:
        event_type (str | Unset):  Default: 'note'.
        description (str | Unset):  Default: ''.
        actor (str | Unset):  Default: ''.
    """

    event_type: str | Unset = "note"
    description: str | Unset = ""
    actor: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type

        description = self.description

        actor = self.actor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if event_type is not UNSET:
            field_dict["event_type"] = event_type
        if description is not UNSET:
            field_dict["description"] = description
        if actor is not UNSET:
            field_dict["actor"] = actor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_type = d.pop("event_type", UNSET)

        description = d.pop("description", UNSET)

        actor = d.pop("actor", UNSET)

        timeline_event_create = cls(
            event_type=event_type,
            description=description,
            actor=actor,
        )

        timeline_event_create.additional_properties = d
        return timeline_event_create

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
