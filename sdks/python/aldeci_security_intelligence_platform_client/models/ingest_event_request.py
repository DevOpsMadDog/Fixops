from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ingest_event_request_raw_data import IngestEventRequestRawData


T = TypeVar("T", bound="IngestEventRequest")


@_attrs_define
class IngestEventRequest:
    """
    Attributes:
        source_system (str | Unset):  Default: ''.
        event_type (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        entity_id (str | Unset):  Default: ''.
        entity_type (str | Unset):  Default: ''.
        raw_data (IngestEventRequestRawData | Unset):
        timestamp (None | str | Unset):
    """

    source_system: str | Unset = ""
    event_type: str | Unset = ""
    severity: str | Unset = "medium"
    entity_id: str | Unset = ""
    entity_type: str | Unset = ""
    raw_data: IngestEventRequestRawData | Unset = UNSET
    timestamp: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_system = self.source_system

        event_type = self.event_type

        severity = self.severity

        entity_id = self.entity_id

        entity_type = self.entity_type

        raw_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.raw_data, Unset):
            raw_data = self.raw_data.to_dict()

        timestamp: None | str | Unset
        if isinstance(self.timestamp, Unset):
            timestamp = UNSET
        else:
            timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if source_system is not UNSET:
            field_dict["source_system"] = source_system
        if event_type is not UNSET:
            field_dict["event_type"] = event_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if entity_id is not UNSET:
            field_dict["entity_id"] = entity_id
        if entity_type is not UNSET:
            field_dict["entity_type"] = entity_type
        if raw_data is not UNSET:
            field_dict["raw_data"] = raw_data
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_event_request_raw_data import IngestEventRequestRawData

        d = dict(src_dict)
        source_system = d.pop("source_system", UNSET)

        event_type = d.pop("event_type", UNSET)

        severity = d.pop("severity", UNSET)

        entity_id = d.pop("entity_id", UNSET)

        entity_type = d.pop("entity_type", UNSET)

        _raw_data = d.pop("raw_data", UNSET)
        raw_data: IngestEventRequestRawData | Unset
        if isinstance(_raw_data, Unset):
            raw_data = UNSET
        else:
            raw_data = IngestEventRequestRawData.from_dict(_raw_data)

        def _parse_timestamp(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        timestamp = _parse_timestamp(d.pop("timestamp", UNSET))

        ingest_event_request = cls(
            source_system=source_system,
            event_type=event_type,
            severity=severity,
            entity_id=entity_id,
            entity_type=entity_type,
            raw_data=raw_data,
            timestamp=timestamp,
        )

        ingest_event_request.additional_properties = d
        return ingest_event_request

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
