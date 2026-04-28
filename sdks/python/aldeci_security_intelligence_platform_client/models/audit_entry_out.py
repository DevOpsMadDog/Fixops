from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.audit_entry_out_details import AuditEntryOutDetails


T = TypeVar("T", bound="AuditEntryOut")


@_attrs_define
class AuditEntryOut:
    """Serialisable audit entry.

    Attributes:
        id (str):
        org_id (str):
        timestamp (str):
        source_format (str):
        severity (str):
        actor (str):
        actor_ip (str):
        action (str):
        resource_type (str):
        resource_id (str):
        outcome (str):
        status (str):
        checksum (str):
        details (AuditEntryOutDetails | Unset):
    """

    id: str
    org_id: str
    timestamp: str
    source_format: str
    severity: str
    actor: str
    actor_ip: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    status: str
    checksum: str
    details: AuditEntryOutDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        org_id = self.org_id

        timestamp = self.timestamp

        source_format = self.source_format

        severity = self.severity

        actor = self.actor

        actor_ip = self.actor_ip

        action = self.action

        resource_type = self.resource_type

        resource_id = self.resource_id

        outcome = self.outcome

        status = self.status

        checksum = self.checksum

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "org_id": org_id,
                "timestamp": timestamp,
                "source_format": source_format,
                "severity": severity,
                "actor": actor,
                "actor_ip": actor_ip,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "outcome": outcome,
                "status": status,
                "checksum": checksum,
            }
        )
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.audit_entry_out_details import AuditEntryOutDetails

        d = dict(src_dict)
        id = d.pop("id")

        org_id = d.pop("org_id")

        timestamp = d.pop("timestamp")

        source_format = d.pop("source_format")

        severity = d.pop("severity")

        actor = d.pop("actor")

        actor_ip = d.pop("actor_ip")

        action = d.pop("action")

        resource_type = d.pop("resource_type")

        resource_id = d.pop("resource_id")

        outcome = d.pop("outcome")

        status = d.pop("status")

        checksum = d.pop("checksum")

        _details = d.pop("details", UNSET)
        details: AuditEntryOutDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = AuditEntryOutDetails.from_dict(_details)

        audit_entry_out = cls(
            id=id,
            org_id=org_id,
            timestamp=timestamp,
            source_format=source_format,
            severity=severity,
            actor=actor,
            actor_ip=actor_ip,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            status=status,
            checksum=checksum,
            details=details,
        )

        audit_entry_out.additional_properties = d
        return audit_entry_out

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
