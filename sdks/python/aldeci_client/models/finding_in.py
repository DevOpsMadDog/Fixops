from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FindingIn")


@_attrs_define
class FindingIn:
    """
    Attributes:
        account_id (str):
        resource_id (str | Unset):  Default: ''.
        resource_type (str | Unset):  Default: ''.
        resource_name (str | Unset):  Default: ''.
        region (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        category (str | Unset):  Default: 'compliance'.
        title (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        remediation (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'open'.
        cis_control (str | Unset):  Default: ''.
        compliance_frameworks (list[str] | Unset):
        risk_score (float | Unset):  Default: 0.0.
    """

    account_id: str
    resource_id: str | Unset = ""
    resource_type: str | Unset = ""
    resource_name: str | Unset = ""
    region: str | Unset = ""
    severity: str | Unset = "medium"
    category: str | Unset = "compliance"
    title: str | Unset = ""
    description: str | Unset = ""
    remediation: str | Unset = ""
    status: str | Unset = "open"
    cis_control: str | Unset = ""
    compliance_frameworks: list[str] | Unset = UNSET
    risk_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        account_id = self.account_id

        resource_id = self.resource_id

        resource_type = self.resource_type

        resource_name = self.resource_name

        region = self.region

        severity = self.severity

        category = self.category

        title = self.title

        description = self.description

        remediation = self.remediation

        status = self.status

        cis_control = self.cis_control

        compliance_frameworks: list[str] | Unset = UNSET
        if not isinstance(self.compliance_frameworks, Unset):
            compliance_frameworks = self.compliance_frameworks

        risk_score = self.risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "account_id": account_id,
            }
        )
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if resource_name is not UNSET:
            field_dict["resource_name"] = resource_name
        if region is not UNSET:
            field_dict["region"] = region
        if severity is not UNSET:
            field_dict["severity"] = severity
        if category is not UNSET:
            field_dict["category"] = category
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if status is not UNSET:
            field_dict["status"] = status
        if cis_control is not UNSET:
            field_dict["cis_control"] = cis_control
        if compliance_frameworks is not UNSET:
            field_dict["compliance_frameworks"] = compliance_frameworks
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        account_id = d.pop("account_id")

        resource_id = d.pop("resource_id", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        resource_name = d.pop("resource_name", UNSET)

        region = d.pop("region", UNSET)

        severity = d.pop("severity", UNSET)

        category = d.pop("category", UNSET)

        title = d.pop("title", UNSET)

        description = d.pop("description", UNSET)

        remediation = d.pop("remediation", UNSET)

        status = d.pop("status", UNSET)

        cis_control = d.pop("cis_control", UNSET)

        compliance_frameworks = cast(list[str], d.pop("compliance_frameworks", UNSET))

        risk_score = d.pop("risk_score", UNSET)

        finding_in = cls(
            account_id=account_id,
            resource_id=resource_id,
            resource_type=resource_type,
            resource_name=resource_name,
            region=region,
            severity=severity,
            category=category,
            title=title,
            description=description,
            remediation=remediation,
            status=status,
            cis_control=cis_control,
            compliance_frameworks=compliance_frameworks,
            risk_score=risk_score,
        )

        finding_in.additional_properties = d
        return finding_in

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
