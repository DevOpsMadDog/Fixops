from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.timeline_event_details import TimelineEventDetails


T = TypeVar("T", bound="TimelineEvent")


@_attrs_define
class TimelineEvent:
    """Event in finding timeline.

    Attributes:
        timestamp (datetime.datetime):
        event_type (str):
        actor (str):
        details (TimelineEventDetails):
    """

    timestamp: datetime.datetime
    event_type: str
    actor: str
    details: TimelineEventDetails
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        timestamp = self.timestamp.isoformat()

        event_type = self.event_type

        actor = self.actor

        details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "timestamp": timestamp,
                "event_type": event_type,
                "actor": actor,
                "details": details,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.timeline_event_details import TimelineEventDetails

        d = dict(src_dict)
        timestamp = isoparse(d.pop("timestamp"))

        event_type = d.pop("event_type")

        actor = d.pop("actor")

        details = TimelineEventDetails.from_dict(d.pop("details"))

        timeline_event = cls(
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            details=details,
        )

        timeline_event.additional_properties = d
        return timeline_event

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
