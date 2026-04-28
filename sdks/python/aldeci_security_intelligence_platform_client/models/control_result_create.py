from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ControlResultCreate")


@_attrs_define
class ControlResultCreate:
    """
    Attributes:
        control_id (str):
        control_name (str | Unset):  Default: ''.
        section (str | Unset):  Default: ''.
        severity (str | Unset): critical/high/medium/low/info Default: 'medium'.
        status (str | Unset): passed/failed/not_applicable/manual_check Default: 'manual_check'.
        evidence (str | Unset):  Default: ''.
        resource_id (str | Unset):  Default: ''.
        resource_type (str | Unset):  Default: ''.
        resource_name (str | Unset):  Default: ''.
        region (str | Unset):  Default: ''.
        remediation (str | Unset):  Default: ''.
        auto_remediated (bool | Unset):  Default: False.
    """

    control_id: str
    control_name: str | Unset = ""
    section: str | Unset = ""
    severity: str | Unset = "medium"
    status: str | Unset = "manual_check"
    evidence: str | Unset = ""
    resource_id: str | Unset = ""
    resource_type: str | Unset = ""
    resource_name: str | Unset = ""
    region: str | Unset = ""
    remediation: str | Unset = ""
    auto_remediated: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        control_name = self.control_name

        section = self.section

        severity = self.severity

        status = self.status

        evidence = self.evidence

        resource_id = self.resource_id

        resource_type = self.resource_type

        resource_name = self.resource_name

        region = self.region

        remediation = self.remediation

        auto_remediated = self.auto_remediated

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
            }
        )
        if control_name is not UNSET:
            field_dict["control_name"] = control_name
        if section is not UNSET:
            field_dict["section"] = section
        if severity is not UNSET:
            field_dict["severity"] = severity
        if status is not UNSET:
            field_dict["status"] = status
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if resource_name is not UNSET:
            field_dict["resource_name"] = resource_name
        if region is not UNSET:
            field_dict["region"] = region
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if auto_remediated is not UNSET:
            field_dict["auto_remediated"] = auto_remediated

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        control_name = d.pop("control_name", UNSET)

        section = d.pop("section", UNSET)

        severity = d.pop("severity", UNSET)

        status = d.pop("status", UNSET)

        evidence = d.pop("evidence", UNSET)

        resource_id = d.pop("resource_id", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        resource_name = d.pop("resource_name", UNSET)

        region = d.pop("region", UNSET)

        remediation = d.pop("remediation", UNSET)

        auto_remediated = d.pop("auto_remediated", UNSET)

        control_result_create = cls(
            control_id=control_id,
            control_name=control_name,
            section=section,
            severity=severity,
            status=status,
            evidence=evidence,
            resource_id=resource_id,
            resource_type=resource_type,
            resource_name=resource_name,
            region=region,
            remediation=remediation,
            auto_remediated=auto_remediated,
        )

        control_result_create.additional_properties = d
        return control_result_create

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
