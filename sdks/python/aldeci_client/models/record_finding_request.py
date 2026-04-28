from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordFindingRequest")


@_attrs_define
class RecordFindingRequest:
    """
    Attributes:
        cloud_account_id (str): Internal cloud account id or account_id
        org_id (str | Unset): Organisation identifier Default: 'default'.
        resource_id (str | Unset): Affected resource identifier Default: ''.
        resource_type (str | Unset): Resource type: iam, storage, compute, network, database, serverless, container
            Default: 'compute'.
        provider (str | Unset): Cloud provider Default: 'aws'.
        severity (str | Unset): Severity: critical, high, medium, low, info Default: 'medium'.
        title (str | Unset): Short finding title Default: ''.
        description (str | Unset): Detailed finding description Default: ''.
        remediation (str | Unset): Remediation steps Default: ''.
        notes (str | Unset): Additional notes Default: ''.
    """

    cloud_account_id: str
    org_id: str | Unset = "default"
    resource_id: str | Unset = ""
    resource_type: str | Unset = "compute"
    provider: str | Unset = "aws"
    severity: str | Unset = "medium"
    title: str | Unset = ""
    description: str | Unset = ""
    remediation: str | Unset = ""
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cloud_account_id = self.cloud_account_id

        org_id = self.org_id

        resource_id = self.resource_id

        resource_type = self.resource_type

        provider = self.provider

        severity = self.severity

        title = self.title

        description = self.description

        remediation = self.remediation

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cloud_account_id": cloud_account_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if provider is not UNSET:
            field_dict["provider"] = provider
        if severity is not UNSET:
            field_dict["severity"] = severity
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cloud_account_id = d.pop("cloud_account_id")

        org_id = d.pop("org_id", UNSET)

        resource_id = d.pop("resource_id", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        provider = d.pop("provider", UNSET)

        severity = d.pop("severity", UNSET)

        title = d.pop("title", UNSET)

        description = d.pop("description", UNSET)

        remediation = d.pop("remediation", UNSET)

        notes = d.pop("notes", UNSET)

        record_finding_request = cls(
            cloud_account_id=cloud_account_id,
            org_id=org_id,
            resource_id=resource_id,
            resource_type=resource_type,
            provider=provider,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            notes=notes,
        )

        record_finding_request.additional_properties = d
        return record_finding_request

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
