from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="OktaEventsResponse")


@_attrs_define
class OktaEventsResponse:
    """
    Attributes:
        received (int): Number of events ingested from this request
        event_types (list[str]): Event types processed
    """

    received: int
    event_types: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        received = self.received

        event_types = self.event_types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "received": received,
                "event_types": event_types,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        received = d.pop("received")

        event_types = cast(list[str], d.pop("event_types"))

        okta_events_response = cls(
            received=received,
            event_types=event_types,
        )

        okta_events_response.additional_properties = d
        return okta_events_response

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
