from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.audit_event_type import AuditEventType
from ..models.audit_severity import AuditSeverity
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.audit_log_create_details import AuditLogCreateDetails


T = TypeVar("T", bound="AuditLogCreate")


@_attrs_define
class AuditLogCreate:
    """Request model for creating an audit log.

    Attributes:
        event_type (AuditEventType): Audit event types.
        action (str):
        severity (AuditSeverity | Unset): Audit event severity.
        user_id (None | str | Unset):
        resource_type (None | str | Unset):
        resource_id (None | str | Unset):
        details (AuditLogCreateDetails | Unset):
        ip_address (None | str | Unset):
        user_agent (None | str | Unset):
    """

    event_type: AuditEventType
    action: str
    severity: AuditSeverity | Unset = UNSET
    user_id: None | str | Unset = UNSET
    resource_type: None | str | Unset = UNSET
    resource_id: None | str | Unset = UNSET
    details: AuditLogCreateDetails | Unset = UNSET
    ip_address: None | str | Unset = UNSET
    user_agent: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type.value

        action = self.action

        severity: str | Unset = UNSET
        if not isinstance(self.severity, Unset):
            severity = self.severity.value

        user_id: None | str | Unset
        if isinstance(self.user_id, Unset):
            user_id = UNSET
        else:
            user_id = self.user_id

        resource_type: None | str | Unset
        if isinstance(self.resource_type, Unset):
            resource_type = UNSET
        else:
            resource_type = self.resource_type

        resource_id: None | str | Unset
        if isinstance(self.resource_id, Unset):
            resource_id = UNSET
        else:
            resource_id = self.resource_id

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        ip_address: None | str | Unset
        if isinstance(self.ip_address, Unset):
            ip_address = UNSET
        else:
            ip_address = self.ip_address

        user_agent: None | str | Unset
        if isinstance(self.user_agent, Unset):
            user_agent = UNSET
        else:
            user_agent = self.user_agent

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_type": event_type,
                "action": action,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if user_id is not UNSET:
            field_dict["user_id"] = user_id
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if details is not UNSET:
            field_dict["details"] = details
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if user_agent is not UNSET:
            field_dict["user_agent"] = user_agent

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.audit_log_create_details import AuditLogCreateDetails

        d = dict(src_dict)
        event_type = AuditEventType(d.pop("event_type"))

        action = d.pop("action")

        _severity = d.pop("severity", UNSET)
        severity: AuditSeverity | Unset
        if isinstance(_severity, Unset):
            severity = UNSET
        else:
            severity = AuditSeverity(_severity)

        def _parse_user_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        user_id = _parse_user_id(d.pop("user_id", UNSET))

        def _parse_resource_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        resource_type = _parse_resource_type(d.pop("resource_type", UNSET))

        def _parse_resource_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        resource_id = _parse_resource_id(d.pop("resource_id", UNSET))

        _details = d.pop("details", UNSET)
        details: AuditLogCreateDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = AuditLogCreateDetails.from_dict(_details)

        def _parse_ip_address(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ip_address = _parse_ip_address(d.pop("ip_address", UNSET))

        def _parse_user_agent(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        user_agent = _parse_user_agent(d.pop("user_agent", UNSET))

        audit_log_create = cls(
            event_type=event_type,
            action=action,
            severity=severity,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        audit_log_create.additional_properties = d
        return audit_log_create

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
