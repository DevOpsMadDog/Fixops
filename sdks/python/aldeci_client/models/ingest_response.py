from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="IngestResponse")


@_attrs_define
class IngestResponse:
    """Response after a single-line ingestion.

    Attributes:
        entry_id (str):
        org_id (str):
        timestamp (str):
        severity (str):
        actor (str):
        action (str):
        checksum (str):
    """

    entry_id: str
    org_id: str
    timestamp: str
    severity: str
    actor: str
    action: str
    checksum: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entry_id = self.entry_id

        org_id = self.org_id

        timestamp = self.timestamp

        severity = self.severity

        actor = self.actor

        action = self.action

        checksum = self.checksum

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entry_id": entry_id,
                "org_id": org_id,
                "timestamp": timestamp,
                "severity": severity,
                "actor": actor,
                "action": action,
                "checksum": checksum,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entry_id = d.pop("entry_id")

        org_id = d.pop("org_id")

        timestamp = d.pop("timestamp")

        severity = d.pop("severity")

        actor = d.pop("actor")

        action = d.pop("action")

        checksum = d.pop("checksum")

        ingest_response = cls(
            entry_id=entry_id,
            org_id=org_id,
            timestamp=timestamp,
            severity=severity,
            actor=actor,
            action=action,
            checksum=checksum,
        )

        ingest_response.additional_properties = d
        return ingest_response

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
