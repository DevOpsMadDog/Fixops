from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.ingest_vendor_request_events_item import IngestVendorRequestEventsItem


T = TypeVar("T", bound="IngestVendorRequest")


@_attrs_define
class IngestVendorRequest:
    """Ingest already-collected events from a third-party IdP.

    Attributes:
        vendor (str): IdP vendor whose raw event format to parse
        realm (str): Target realm / org_id for the events
        events (list[IngestVendorRequestEventsItem]): Raw vendor events (max 1000)
    """

    vendor: str
    realm: str
    events: list[IngestVendorRequestEventsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor = self.vendor

        realm = self.realm

        events = []
        for events_item_data in self.events:
            events_item = events_item_data.to_dict()
            events.append(events_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor": vendor,
                "realm": realm,
                "events": events,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_vendor_request_events_item import IngestVendorRequestEventsItem

        d = dict(src_dict)
        vendor = d.pop("vendor")

        realm = d.pop("realm")

        events = []
        _events = d.pop("events")
        for events_item_data in _events:
            events_item = IngestVendorRequestEventsItem.from_dict(events_item_data)

            events.append(events_item)

        ingest_vendor_request = cls(
            vendor=vendor,
            realm=realm,
            events=events,
        )

        ingest_vendor_request.additional_properties = d
        return ingest_vendor_request

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
