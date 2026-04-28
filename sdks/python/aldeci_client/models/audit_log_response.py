from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.audit_log_response_details import AuditLogResponseDetails


T = TypeVar("T", bound="AuditLogResponse")


@_attrs_define
class AuditLogResponse:
    """Response model for an audit log.

    Attributes:
        id (str):
        event_type (str):
        severity (str):
        user_id (None | str):
        resource_type (None | str):
        resource_id (None | str):
        action (str):
        details (AuditLogResponseDetails):
        ip_address (None | str):
        user_agent (None | str):
        timestamp (str):
    """

    id: str
    event_type: str
    severity: str
    user_id: None | str
    resource_type: None | str
    resource_id: None | str
    action: str
    details: AuditLogResponseDetails
    ip_address: None | str
    user_agent: None | str
    timestamp: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        event_type = self.event_type

        severity = self.severity

        user_id: None | str
        user_id = self.user_id

        resource_type: None | str
        resource_type = self.resource_type

        resource_id: None | str
        resource_id = self.resource_id

        action = self.action

        details = self.details.to_dict()

        ip_address: None | str
        ip_address = self.ip_address

        user_agent: None | str
        user_agent = self.user_agent

        timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "event_type": event_type,
                "severity": severity,
                "user_id": user_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "action": action,
                "details": details,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "timestamp": timestamp,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.audit_log_response_details import AuditLogResponseDetails

        d = dict(src_dict)
        id = d.pop("id")

        event_type = d.pop("event_type")

        severity = d.pop("severity")

        def _parse_user_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        user_id = _parse_user_id(d.pop("user_id"))

        def _parse_resource_type(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        resource_type = _parse_resource_type(d.pop("resource_type"))

        def _parse_resource_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        resource_id = _parse_resource_id(d.pop("resource_id"))

        action = d.pop("action")

        details = AuditLogResponseDetails.from_dict(d.pop("details"))

        def _parse_ip_address(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        ip_address = _parse_ip_address(d.pop("ip_address"))

        def _parse_user_agent(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        user_agent = _parse_user_agent(d.pop("user_agent"))

        timestamp = d.pop("timestamp")

        audit_log_response = cls(
            id=id,
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=timestamp,
        )

        audit_log_response.additional_properties = d
        return audit_log_response

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
