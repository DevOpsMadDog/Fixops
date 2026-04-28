from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.event_bus_status_response_metrics import EventBusStatusResponseMetrics
    from ..models.event_bus_status_response_queue import EventBusStatusResponseQueue
    from ..models.event_bus_status_response_registered_handlers import EventBusStatusResponseRegisteredHandlers


T = TypeVar("T", bound="EventBusStatusResponse")


@_attrs_define
class EventBusStatusResponse:
    """
    Attributes:
        enabled (bool):
        enabled_event_types (list[str]):
        registered_handlers (EventBusStatusResponseRegisteredHandlers):
        metrics (EventBusStatusResponseMetrics):
        queue (EventBusStatusResponseQueue):
    """

    enabled: bool
    enabled_event_types: list[str]
    registered_handlers: EventBusStatusResponseRegisteredHandlers
    metrics: EventBusStatusResponseMetrics
    queue: EventBusStatusResponseQueue
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enabled = self.enabled

        enabled_event_types = self.enabled_event_types

        registered_handlers = self.registered_handlers.to_dict()

        metrics = self.metrics.to_dict()

        queue = self.queue.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "enabled": enabled,
                "enabled_event_types": enabled_event_types,
                "registered_handlers": registered_handlers,
                "metrics": metrics,
                "queue": queue,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.event_bus_status_response_metrics import EventBusStatusResponseMetrics
        from ..models.event_bus_status_response_queue import EventBusStatusResponseQueue
        from ..models.event_bus_status_response_registered_handlers import EventBusStatusResponseRegisteredHandlers

        d = dict(src_dict)
        enabled = d.pop("enabled")

        enabled_event_types = cast(list[str], d.pop("enabled_event_types"))

        registered_handlers = EventBusStatusResponseRegisteredHandlers.from_dict(d.pop("registered_handlers"))

        metrics = EventBusStatusResponseMetrics.from_dict(d.pop("metrics"))

        queue = EventBusStatusResponseQueue.from_dict(d.pop("queue"))

        event_bus_status_response = cls(
            enabled=enabled,
            enabled_event_types=enabled_event_types,
            registered_handlers=registered_handlers,
            metrics=metrics,
            queue=queue,
        )

        event_bus_status_response.additional_properties = d
        return event_bus_status_response

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
