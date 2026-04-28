from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.rasp_mode import RaspMode
from ..models.threat_category import ThreatCategory
from ..models.threat_severity import ThreatSeverity
from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatEvent")


@_attrs_define
class ThreatEvent:
    """A detected threat event.

    Attributes:
        rule_id (str):
        category (ThreatCategory): OWASP-aligned threat categories.
        severity (ThreatSeverity): Threat severity levels.
        confidence (float):
        client_ip (str):
        method (str):
        path (str):
        matched_value (str):
        matched_field (str):
        action_taken (RaspMode): Operating mode for the RASP engine.
        event_id (str | Unset):
        timestamp (datetime.datetime | Unset):
        api_key (None | str | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    rule_id: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float
    client_ip: str
    method: str
    path: str
    matched_value: str
    matched_field: str
    action_taken: RaspMode
    event_id: str | Unset = UNSET
    timestamp: datetime.datetime | Unset = UNSET
    api_key: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_id = self.rule_id

        category = self.category.value

        severity = self.severity.value

        confidence = self.confidence

        client_ip = self.client_ip

        method = self.method

        path = self.path

        matched_value = self.matched_value

        matched_field = self.matched_field

        action_taken = self.action_taken.value

        event_id = self.event_id

        timestamp: str | Unset = UNSET
        if not isinstance(self.timestamp, Unset):
            timestamp = self.timestamp.isoformat()

        api_key: None | str | Unset
        if isinstance(self.api_key, Unset):
            api_key = UNSET
        else:
            api_key = self.api_key

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_id": rule_id,
                "category": category,
                "severity": severity,
                "confidence": confidence,
                "client_ip": client_ip,
                "method": method,
                "path": path,
                "matched_value": matched_value,
                "matched_field": matched_field,
                "action_taken": action_taken,
            }
        )
        if event_id is not UNSET:
            field_dict["event_id"] = event_id
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if api_key is not UNSET:
            field_dict["api_key"] = api_key
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_id = d.pop("rule_id")

        category = ThreatCategory(d.pop("category"))

        severity = ThreatSeverity(d.pop("severity"))

        confidence = d.pop("confidence")

        client_ip = d.pop("client_ip")

        method = d.pop("method")

        path = d.pop("path")

        matched_value = d.pop("matched_value")

        matched_field = d.pop("matched_field")

        action_taken = RaspMode(d.pop("action_taken"))

        event_id = d.pop("event_id", UNSET)

        _timestamp = d.pop("timestamp", UNSET)
        timestamp: datetime.datetime | Unset
        if isinstance(_timestamp, Unset):
            timestamp = UNSET
        else:
            timestamp = isoparse(_timestamp)

        def _parse_api_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_key = _parse_api_key(d.pop("api_key", UNSET))

        org_id = d.pop("org_id", UNSET)

        threat_event = cls(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            client_ip=client_ip,
            method=method,
            path=path,
            matched_value=matched_value,
            matched_field=matched_field,
            action_taken=action_taken,
            event_id=event_id,
            timestamp=timestamp,
            api_key=api_key,
            org_id=org_id,
        )

        threat_event.additional_properties = d
        return threat_event

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
