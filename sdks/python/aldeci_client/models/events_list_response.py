from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.webhook_event_out import WebhookEventOut


T = TypeVar("T", bound="EventsListResponse")


@_attrs_define
class EventsListResponse:
    """
    Attributes:
        total (int):
        events (list[WebhookEventOut]):
    """

    total: int
    events: list[WebhookEventOut]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total = self.total

        events = []
        for events_item_data in self.events:
            events_item = events_item_data.to_dict()
            events.append(events_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total": total,
                "events": events,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.webhook_event_out import WebhookEventOut

        d = dict(src_dict)
        total = d.pop("total")

        events = []
        _events = d.pop("events")
        for events_item_data in _events:
            events_item = WebhookEventOut.from_dict(events_item_data)

            events.append(events_item)

        events_list_response = cls(
            total=total,
            events=events,
        )

        events_list_response.additional_properties = d
        return events_list_response

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
