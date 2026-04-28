from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordMisconfigRequest")


@_attrs_define
class RecordMisconfigRequest:
    """
    Attributes:
        account_id (str):
        provider (str | Unset):  Default: 'aws'.
        service (str | Unset):  Default: 's3'.
        check_name (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        resource_id (str | Unset):  Default: ''.
        resource_name (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        remediation (str | Unset):  Default: ''.
        compliant (bool | Unset):  Default: False.
    """

    account_id: str
    provider: str | Unset = "aws"
    service: str | Unset = "s3"
    check_name: str | Unset = ""
    severity: str | Unset = "medium"
    resource_id: str | Unset = ""
    resource_name: str | Unset = ""
    description: str | Unset = ""
    remediation: str | Unset = ""
    compliant: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        account_id = self.account_id

        provider = self.provider

        service = self.service

        check_name = self.check_name

        severity = self.severity

        resource_id = self.resource_id

        resource_name = self.resource_name

        description = self.description

        remediation = self.remediation

        compliant = self.compliant

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "account_id": account_id,
            }
        )
        if provider is not UNSET:
            field_dict["provider"] = provider
        if service is not UNSET:
            field_dict["service"] = service
        if check_name is not UNSET:
            field_dict["check_name"] = check_name
        if severity is not UNSET:
            field_dict["severity"] = severity
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if resource_name is not UNSET:
            field_dict["resource_name"] = resource_name
        if description is not UNSET:
            field_dict["description"] = description
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if compliant is not UNSET:
            field_dict["compliant"] = compliant

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        account_id = d.pop("account_id")

        provider = d.pop("provider", UNSET)

        service = d.pop("service", UNSET)

        check_name = d.pop("check_name", UNSET)

        severity = d.pop("severity", UNSET)

        resource_id = d.pop("resource_id", UNSET)

        resource_name = d.pop("resource_name", UNSET)

        description = d.pop("description", UNSET)

        remediation = d.pop("remediation", UNSET)

        compliant = d.pop("compliant", UNSET)

        record_misconfig_request = cls(
            account_id=account_id,
            provider=provider,
            service=service,
            check_name=check_name,
            severity=severity,
            resource_id=resource_id,
            resource_name=resource_name,
            description=description,
            remediation=remediation,
            compliant=compliant,
        )

        record_misconfig_request.additional_properties = d
        return record_misconfig_request

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
