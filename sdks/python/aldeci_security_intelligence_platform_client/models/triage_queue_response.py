from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.triage_queue_item import TriageQueueItem
    from ..models.triage_queue_response_buckets import TriageQueueResponseBuckets


T = TypeVar("T", bound="TriageQueueResponse")


@_attrs_define
class TriageQueueResponse:
    """Response for /queue.

    Attributes:
        queue (list[TriageQueueItem]):
        total (int):
        buckets (TriageQueueResponseBuckets):
        timestamp (str):
    """

    queue: list[TriageQueueItem]
    total: int
    buckets: TriageQueueResponseBuckets
    timestamp: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        queue = []
        for queue_item_data in self.queue:
            queue_item = queue_item_data.to_dict()
            queue.append(queue_item)

        total = self.total

        buckets = self.buckets.to_dict()

        timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "queue": queue,
                "total": total,
                "buckets": buckets,
                "timestamp": timestamp,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.triage_queue_item import TriageQueueItem
        from ..models.triage_queue_response_buckets import TriageQueueResponseBuckets

        d = dict(src_dict)
        queue = []
        _queue = d.pop("queue")
        for queue_item_data in _queue:
            queue_item = TriageQueueItem.from_dict(queue_item_data)

            queue.append(queue_item)

        total = d.pop("total")

        buckets = TriageQueueResponseBuckets.from_dict(d.pop("buckets"))

        timestamp = d.pop("timestamp")

        triage_queue_response = cls(
            queue=queue,
            total=total,
            buckets=buckets,
            timestamp=timestamp,
        )

        triage_queue_response.additional_properties = d
        return triage_queue_response

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
