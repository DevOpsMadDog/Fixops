from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordIncidentRequest")


@_attrs_define
class RecordIncidentRequest:
    """
    Attributes:
        endpoint_id (str):
        abuse_type (str):
        severity (str):
        source_ip (None | str | Unset):
        request_count (int | Unset):  Default: 0.
        time_window_seconds (int | Unset):  Default: 60.
        blocked (bool | Unset):  Default: False.
        status (str | Unset):  Default: 'open'.
        detected_at (None | str | Unset):
    """

    endpoint_id: str
    abuse_type: str
    severity: str
    source_ip: None | str | Unset = UNSET
    request_count: int | Unset = 0
    time_window_seconds: int | Unset = 60
    blocked: bool | Unset = False
    status: str | Unset = "open"
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        endpoint_id = self.endpoint_id

        abuse_type = self.abuse_type

        severity = self.severity

        source_ip: None | str | Unset
        if isinstance(self.source_ip, Unset):
            source_ip = UNSET
        else:
            source_ip = self.source_ip

        request_count = self.request_count

        time_window_seconds = self.time_window_seconds

        blocked = self.blocked

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
                "endpoint_id": endpoint_id,
                "abuse_type": abuse_type,
                "severity": severity,
            }
        )
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if request_count is not UNSET:
            field_dict["request_count"] = request_count
        if time_window_seconds is not UNSET:
            field_dict["time_window_seconds"] = time_window_seconds
        if blocked is not UNSET:
            field_dict["blocked"] = blocked
        if status is not UNSET:
            field_dict["status"] = status
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        endpoint_id = d.pop("endpoint_id")

        abuse_type = d.pop("abuse_type")

        severity = d.pop("severity")

        def _parse_source_ip(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_ip = _parse_source_ip(d.pop("source_ip", UNSET))

        request_count = d.pop("request_count", UNSET)

        time_window_seconds = d.pop("time_window_seconds", UNSET)

        blocked = d.pop("blocked", UNSET)

        status = d.pop("status", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        record_incident_request = cls(
            endpoint_id=endpoint_id,
            abuse_type=abuse_type,
            severity=severity,
            source_ip=source_ip,
            request_count=request_count,
            time_window_seconds=time_window_seconds,
            blocked=blocked,
            status=status,
            detected_at=detected_at,
        )

        record_incident_request.additional_properties = d
        return record_incident_request

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
