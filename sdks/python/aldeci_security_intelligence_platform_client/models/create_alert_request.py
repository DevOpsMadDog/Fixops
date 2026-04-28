from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAlertRequest")


@_attrs_define
class CreateAlertRequest:
    """
    Attributes:
        endpoint_id (str): Target endpoint ID
        org_id (str | Unset): Organisation ID Default: 'default'.
        severity (str | Unset): critical/high/medium/low Default: 'medium'.
        alert_type (str | Unset): malware/ransomware/lateral_movement/privilege_escalation/data_exfil/policy_violation
            Default: 'policy_violation'.
        description (str | Unset): Alert description Default: ''.
        status (str | Unset): open/investigating/resolved Default: 'open'.
    """

    endpoint_id: str
    org_id: str | Unset = "default"
    severity: str | Unset = "medium"
    alert_type: str | Unset = "policy_violation"
    description: str | Unset = ""
    status: str | Unset = "open"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        endpoint_id = self.endpoint_id

        org_id = self.org_id

        severity = self.severity

        alert_type = self.alert_type

        description = self.description

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "endpoint_id": endpoint_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if alert_type is not UNSET:
            field_dict["alert_type"] = alert_type
        if description is not UNSET:
            field_dict["description"] = description
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        endpoint_id = d.pop("endpoint_id")

        org_id = d.pop("org_id", UNSET)

        severity = d.pop("severity", UNSET)

        alert_type = d.pop("alert_type", UNSET)

        description = d.pop("description", UNSET)

        status = d.pop("status", UNSET)

        create_alert_request = cls(
            endpoint_id=endpoint_id,
            org_id=org_id,
            severity=severity,
            alert_type=alert_type,
            description=description,
            status=status,
        )

        create_alert_request.additional_properties = d
        return create_alert_request

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
