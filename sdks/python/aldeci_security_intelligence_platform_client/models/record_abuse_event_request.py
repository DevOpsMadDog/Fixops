from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordAbuseEventRequest")


@_attrs_define
class RecordAbuseEventRequest:
    """
    Attributes:
        event_type (str): Abuse event type (bola, injection, auth_bypass, etc.)
        org_id (str | Unset): Organisation ID Default: 'default'.
        severity (str | Unset): one of: critical/high/medium/low Default: 'medium'.
        source_ip (str | Unset): Source IP address Default: ''.
        api_key_id (str | Unset): Associated API key ID if known Default: ''.
        endpoint_id (str | Unset): Associated endpoint ID if known Default: ''.
        request_payload_preview (str | Unset): Sanitised request payload preview Default: ''.
        status (str | Unset): one of: detected/investigating/blocked/false_positive Default: 'detected'.
    """

    event_type: str
    org_id: str | Unset = "default"
    severity: str | Unset = "medium"
    source_ip: str | Unset = ""
    api_key_id: str | Unset = ""
    endpoint_id: str | Unset = ""
    request_payload_preview: str | Unset = ""
    status: str | Unset = "detected"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type

        org_id = self.org_id

        severity = self.severity

        source_ip = self.source_ip

        api_key_id = self.api_key_id

        endpoint_id = self.endpoint_id

        request_payload_preview = self.request_payload_preview

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_type": event_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if api_key_id is not UNSET:
            field_dict["api_key_id"] = api_key_id
        if endpoint_id is not UNSET:
            field_dict["endpoint_id"] = endpoint_id
        if request_payload_preview is not UNSET:
            field_dict["request_payload_preview"] = request_payload_preview
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_type = d.pop("event_type")

        org_id = d.pop("org_id", UNSET)

        severity = d.pop("severity", UNSET)

        source_ip = d.pop("source_ip", UNSET)

        api_key_id = d.pop("api_key_id", UNSET)

        endpoint_id = d.pop("endpoint_id", UNSET)

        request_payload_preview = d.pop("request_payload_preview", UNSET)

        status = d.pop("status", UNSET)

        record_abuse_event_request = cls(
            event_type=event_type,
            org_id=org_id,
            severity=severity,
            source_ip=source_ip,
            api_key_id=api_key_id,
            endpoint_id=endpoint_id,
            request_payload_preview=request_payload_preview,
            status=status,
        )

        record_abuse_event_request.additional_properties = d
        return record_abuse_event_request

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
