from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.timeline_event_out import TimelineEventOut


T = TypeVar("T", bound="ForensicTimelineOut")


@_attrs_define
class ForensicTimelineOut:
    """
    Attributes:
        query (str):
        start (str):
        end (str):
        total (int):
        actors (list[str]):
        resources (list[str]):
        events (list[TimelineEventOut]):
    """

    query: str
    start: str
    end: str
    total: int
    actors: list[str]
    resources: list[str]
    events: list[TimelineEventOut]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        start = self.start

        end = self.end

        total = self.total

        actors = self.actors

        resources = self.resources

        events = []
        for events_item_data in self.events:
            events_item = events_item_data.to_dict()
            events.append(events_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
                "start": start,
                "end": end,
                "total": total,
                "actors": actors,
                "resources": resources,
                "events": events,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.timeline_event_out import TimelineEventOut

        d = dict(src_dict)
        query = d.pop("query")

        start = d.pop("start")

        end = d.pop("end")

        total = d.pop("total")

        actors = cast(list[str], d.pop("actors"))

        resources = cast(list[str], d.pop("resources"))

        events = []
        _events = d.pop("events")
        for events_item_data in _events:
            events_item = TimelineEventOut.from_dict(events_item_data)

            events.append(events_item)

        forensic_timeline_out = cls(
            query=query,
            start=start,
            end=end,
            total=total,
            actors=actors,
            resources=resources,
            events=events,
        )

        forensic_timeline_out.additional_properties = d
        return forensic_timeline_out

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
