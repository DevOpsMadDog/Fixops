from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.event_type import EventType
from ..models.threat_level import ThreatLevel
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.event_ingest_request_details import EventIngestRequestDetails


T = TypeVar("T", bound="EventIngestRequest")


@_attrs_define
class EventIngestRequest:
    """Request body for ingesting a runtime event.

    Attributes:
        event_type (EventType): Categories of host-level runtime events.
        source_host (str):
        process_name (str):
        user (str):
        details (EventIngestRequestDetails | Unset):
        threat_level (ThreatLevel | Unset): Severity of a detected runtime threat.
    """

    event_type: EventType
    source_host: str
    process_name: str
    user: str
    details: EventIngestRequestDetails | Unset = UNSET
    threat_level: ThreatLevel | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type.value

        source_host = self.source_host

        process_name = self.process_name

        user = self.user

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        threat_level: str | Unset = UNSET
        if not isinstance(self.threat_level, Unset):
            threat_level = self.threat_level.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_type": event_type,
                "source_host": source_host,
                "process_name": process_name,
                "user": user,
            }
        )
        if details is not UNSET:
            field_dict["details"] = details
        if threat_level is not UNSET:
            field_dict["threat_level"] = threat_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.event_ingest_request_details import EventIngestRequestDetails

        d = dict(src_dict)
        event_type = EventType(d.pop("event_type"))

        source_host = d.pop("source_host")

        process_name = d.pop("process_name")

        user = d.pop("user")

        _details = d.pop("details", UNSET)
        details: EventIngestRequestDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = EventIngestRequestDetails.from_dict(_details)

        _threat_level = d.pop("threat_level", UNSET)
        threat_level: ThreatLevel | Unset
        if isinstance(_threat_level, Unset):
            threat_level = UNSET
        else:
            threat_level = ThreatLevel(_threat_level)

        event_ingest_request = cls(
            event_type=event_type,
            source_host=source_host,
            process_name=process_name,
            user=user,
            details=details,
            threat_level=threat_level,
        )

        event_ingest_request.additional_properties = d
        return event_ingest_request

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
