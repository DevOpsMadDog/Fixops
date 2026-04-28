from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.falcon_ingest_request_events_type_0_item import FalconIngestRequestEventsType0Item


T = TypeVar("T", bound="FalconIngestRequest")


@_attrs_define
class FalconIngestRequest:
    """Ingest a Falcon Detection.Created dump.

    Exactly one of ``events`` (a list of detection dicts) or ``json_text``
    (raw JSON / NDJSON string) must be supplied. ``org_id`` selects the
    target ALDECI tenant for isolation.

        Attributes:
            org_id (str | Unset):  Default: 'default'.
            events (list[FalconIngestRequestEventsType0Item] | None | Unset): List of Falcon Detection.Created event dicts.
            json_text (None | str | Unset): Raw JSON string (array, single object, or NDJSON).
            max_events (int | None | Unset): Optional cap on number of events to process.
    """

    org_id: str | Unset = "default"
    events: list[FalconIngestRequestEventsType0Item] | None | Unset = UNSET
    json_text: None | str | Unset = UNSET
    max_events: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        events: list[dict[str, Any]] | None | Unset
        if isinstance(self.events, Unset):
            events = UNSET
        elif isinstance(self.events, list):
            events = []
            for events_type_0_item_data in self.events:
                events_type_0_item = events_type_0_item_data.to_dict()
                events.append(events_type_0_item)

        else:
            events = self.events

        json_text: None | str | Unset
        if isinstance(self.json_text, Unset):
            json_text = UNSET
        else:
            json_text = self.json_text

        max_events: int | None | Unset
        if isinstance(self.max_events, Unset):
            max_events = UNSET
        else:
            max_events = self.max_events

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if events is not UNSET:
            field_dict["events"] = events
        if json_text is not UNSET:
            field_dict["json_text"] = json_text
        if max_events is not UNSET:
            field_dict["max_events"] = max_events

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.falcon_ingest_request_events_type_0_item import FalconIngestRequestEventsType0Item

        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        def _parse_events(data: object) -> list[FalconIngestRequestEventsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                events_type_0 = []
                _events_type_0 = data
                for events_type_0_item_data in _events_type_0:
                    events_type_0_item = FalconIngestRequestEventsType0Item.from_dict(events_type_0_item_data)

                    events_type_0.append(events_type_0_item)

                return events_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[FalconIngestRequestEventsType0Item] | None | Unset, data)

        events = _parse_events(d.pop("events", UNSET))

        def _parse_json_text(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        json_text = _parse_json_text(d.pop("json_text", UNSET))

        def _parse_max_events(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        max_events = _parse_max_events(d.pop("max_events", UNSET))

        falcon_ingest_request = cls(
            org_id=org_id,
            events=events,
            json_text=json_text,
            max_events=max_events,
        )

        falcon_ingest_request.additional_properties = d
        return falcon_ingest_request

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
