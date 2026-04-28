from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ingest_signal_request_raw_data import IngestSignalRequestRawData


T = TypeVar("T", bound="IngestSignalRequest")


@_attrs_define
class IngestSignalRequest:
    """
    Attributes:
        source_type (str | Unset): endpoint/network/cloud/identity/email/application/threat_intel Default: 'endpoint'.
        source_system (str | Unset):  Default: ''.
        signal_type (str | Unset): malware/lateral_movement/credential_theft/exfiltration/c2/anomaly/policy_violation
            Default: 'anomaly'.
        severity (str | Unset): critical/high/medium/low/info Default: 'medium'.
        entity_id (str | Unset): IP, hostname, username, file hash, etc. Default: ''.
        entity_type (str | Unset): host/ip/user/file/process/domain Default: 'host'.
        raw_data (IngestSignalRequestRawData | Unset):
        confidence (float | Unset):  Default: 0.8.
        ingested_at (None | str | Unset):
    """

    source_type: str | Unset = "endpoint"
    source_system: str | Unset = ""
    signal_type: str | Unset = "anomaly"
    severity: str | Unset = "medium"
    entity_id: str | Unset = ""
    entity_type: str | Unset = "host"
    raw_data: IngestSignalRequestRawData | Unset = UNSET
    confidence: float | Unset = 0.8
    ingested_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_type = self.source_type

        source_system = self.source_system

        signal_type = self.signal_type

        severity = self.severity

        entity_id = self.entity_id

        entity_type = self.entity_type

        raw_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.raw_data, Unset):
            raw_data = self.raw_data.to_dict()

        confidence = self.confidence

        ingested_at: None | str | Unset
        if isinstance(self.ingested_at, Unset):
            ingested_at = UNSET
        else:
            ingested_at = self.ingested_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if source_type is not UNSET:
            field_dict["source_type"] = source_type
        if source_system is not UNSET:
            field_dict["source_system"] = source_system
        if signal_type is not UNSET:
            field_dict["signal_type"] = signal_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if entity_id is not UNSET:
            field_dict["entity_id"] = entity_id
        if entity_type is not UNSET:
            field_dict["entity_type"] = entity_type
        if raw_data is not UNSET:
            field_dict["raw_data"] = raw_data
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if ingested_at is not UNSET:
            field_dict["ingested_at"] = ingested_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_signal_request_raw_data import IngestSignalRequestRawData

        d = dict(src_dict)
        source_type = d.pop("source_type", UNSET)

        source_system = d.pop("source_system", UNSET)

        signal_type = d.pop("signal_type", UNSET)

        severity = d.pop("severity", UNSET)

        entity_id = d.pop("entity_id", UNSET)

        entity_type = d.pop("entity_type", UNSET)

        _raw_data = d.pop("raw_data", UNSET)
        raw_data: IngestSignalRequestRawData | Unset
        if isinstance(_raw_data, Unset):
            raw_data = UNSET
        else:
            raw_data = IngestSignalRequestRawData.from_dict(_raw_data)

        confidence = d.pop("confidence", UNSET)

        def _parse_ingested_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ingested_at = _parse_ingested_at(d.pop("ingested_at", UNSET))

        ingest_signal_request = cls(
            source_type=source_type,
            source_system=source_system,
            signal_type=signal_type,
            severity=severity,
            entity_id=entity_id,
            entity_type=entity_type,
            raw_data=raw_data,
            confidence=confidence,
            ingested_at=ingested_at,
        )

        ingest_signal_request.additional_properties = d
        return ingest_signal_request

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
