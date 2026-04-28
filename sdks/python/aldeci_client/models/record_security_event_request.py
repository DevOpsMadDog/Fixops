from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordSecurityEventRequest")


@_attrs_define
class RecordSecurityEventRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        api_id (str): API UUID
        event_type (str): auth_failure | rate_exceeded | injection | schema_violation | bot
        source_ip (str): Attacking source IP
        request_path (str | Unset): Request path that triggered the event Default: ''.
        severity (str | Unset): low | medium | high | critical Default: 'medium'.
    """

    org_id: str
    api_id: str
    event_type: str
    source_ip: str
    request_path: str | Unset = ""
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        api_id = self.api_id

        event_type = self.event_type

        source_ip = self.source_ip

        request_path = self.request_path

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "api_id": api_id,
                "event_type": event_type,
                "source_ip": source_ip,
            }
        )
        if request_path is not UNSET:
            field_dict["request_path"] = request_path
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        api_id = d.pop("api_id")

        event_type = d.pop("event_type")

        source_ip = d.pop("source_ip")

        request_path = d.pop("request_path", UNSET)

        severity = d.pop("severity", UNSET)

        record_security_event_request = cls(
            org_id=org_id,
            api_id=api_id,
            event_type=event_type,
            source_ip=source_ip,
            request_path=request_path,
            severity=severity,
        )

        record_security_event_request.additional_properties = d
        return record_security_event_request

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
