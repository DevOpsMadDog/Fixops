from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AbuseEventCreate")


@_attrs_define
class AbuseEventCreate:
    """
    Attributes:
        event_type (str):
        api_key_id (str | Unset):  Default: ''.
        endpoint_id (str | Unset):  Default: ''.
        source_ip (str | Unset):  Default: ''.
        request_payload_preview (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        status (str | Unset):  Default: 'detected'.
        detected_at (None | str | Unset):
    """

    event_type: str
    api_key_id: str | Unset = ""
    endpoint_id: str | Unset = ""
    source_ip: str | Unset = ""
    request_payload_preview: str | Unset = ""
    severity: str | Unset = "medium"
    status: str | Unset = "detected"
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type

        api_key_id = self.api_key_id

        endpoint_id = self.endpoint_id

        source_ip = self.source_ip

        request_payload_preview = self.request_payload_preview

        severity = self.severity

        status = self.status

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_type": event_type,
            }
        )
        if api_key_id is not UNSET:
            field_dict["api_key_id"] = api_key_id
        if endpoint_id is not UNSET:
            field_dict["endpoint_id"] = endpoint_id
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if request_payload_preview is not UNSET:
            field_dict["request_payload_preview"] = request_payload_preview
        if severity is not UNSET:
            field_dict["severity"] = severity
        if status is not UNSET:
            field_dict["status"] = status
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_type = d.pop("event_type")

        api_key_id = d.pop("api_key_id", UNSET)

        endpoint_id = d.pop("endpoint_id", UNSET)

        source_ip = d.pop("source_ip", UNSET)

        request_payload_preview = d.pop("request_payload_preview", UNSET)

        severity = d.pop("severity", UNSET)

        status = d.pop("status", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        abuse_event_create = cls(
            event_type=event_type,
            api_key_id=api_key_id,
            endpoint_id=endpoint_id,
            source_ip=source_ip,
            request_payload_preview=request_payload_preview,
            severity=severity,
            status=status,
            detected_at=detected_at,
        )

        abuse_event_create.additional_properties = d
        return abuse_event_create

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
