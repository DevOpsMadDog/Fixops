from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="EventBusQueueResponse")


@_attrs_define
class EventBusQueueResponse:
    """
    Attributes:
        queued (int):
        indexed (int):
        failed (int):
        total (int):
        max_size (int):
    """

    queued: int
    indexed: int
    failed: int
    total: int
    max_size: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        queued = self.queued

        indexed = self.indexed

        failed = self.failed

        total = self.total

        max_size = self.max_size

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "queued": queued,
                "indexed": indexed,
                "failed": failed,
                "total": total,
                "max_size": max_size,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        queued = d.pop("queued")

        indexed = d.pop("indexed")

        failed = d.pop("failed")

        total = d.pop("total")

        max_size = d.pop("max_size")

        event_bus_queue_response = cls(
            queued=queued,
            indexed=indexed,
            failed=failed,
            total=total,
            max_size=max_size,
        )

        event_bus_queue_response.additional_properties = d
        return event_bus_queue_response

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
