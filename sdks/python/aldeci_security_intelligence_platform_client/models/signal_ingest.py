from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SignalIngest")


@_attrs_define
class SignalIngest:
    """
    Attributes:
        entity_value (str):
        signal_type (str | Unset):  Default: 'alert'.
        source_engine (str | Unset):  Default: 'siem'.
        signal_id (str | Unset):  Default: ''.
        entity_type (str | Unset):  Default: 'ip'.
        severity (str | Unset):  Default: 'medium'.
        description (str | Unset):  Default: ''.
        timestamp (None | str | Unset):
        ttl_minutes (int | Unset):  Default: 1440.
    """

    entity_value: str
    signal_type: str | Unset = "alert"
    source_engine: str | Unset = "siem"
    signal_id: str | Unset = ""
    entity_type: str | Unset = "ip"
    severity: str | Unset = "medium"
    description: str | Unset = ""
    timestamp: None | str | Unset = UNSET
    ttl_minutes: int | Unset = 1440
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_value = self.entity_value

        signal_type = self.signal_type

        source_engine = self.source_engine

        signal_id = self.signal_id

        entity_type = self.entity_type

        severity = self.severity

        description = self.description

        timestamp: None | str | Unset
        if isinstance(self.timestamp, Unset):
            timestamp = UNSET
        else:
            timestamp = self.timestamp

        ttl_minutes = self.ttl_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_value": entity_value,
            }
        )
        if signal_type is not UNSET:
            field_dict["signal_type"] = signal_type
        if source_engine is not UNSET:
            field_dict["source_engine"] = source_engine
        if signal_id is not UNSET:
            field_dict["signal_id"] = signal_id
        if entity_type is not UNSET:
            field_dict["entity_type"] = entity_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if ttl_minutes is not UNSET:
            field_dict["ttl_minutes"] = ttl_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entity_value = d.pop("entity_value")

        signal_type = d.pop("signal_type", UNSET)

        source_engine = d.pop("source_engine", UNSET)

        signal_id = d.pop("signal_id", UNSET)

        entity_type = d.pop("entity_type", UNSET)

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        def _parse_timestamp(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        timestamp = _parse_timestamp(d.pop("timestamp", UNSET))

        ttl_minutes = d.pop("ttl_minutes", UNSET)

        signal_ingest = cls(
            entity_value=entity_value,
            signal_type=signal_type,
            source_engine=source_engine,
            signal_id=signal_id,
            entity_type=entity_type,
            severity=severity,
            description=description,
            timestamp=timestamp,
            ttl_minutes=ttl_minutes,
        )

        signal_ingest.additional_properties = d
        return signal_ingest

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
