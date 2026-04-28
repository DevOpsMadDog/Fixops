from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddLicenseRecordRequest")


@_attrs_define
class AddLicenseRecordRequest:
    """
    Attributes:
        package_name (str):
        org_id (str | Unset):  Default: 'default'.
        package_version (str | Unset):  Default: ''.
        license_type (str | Unset):  Default: 'unknown'.
        license_risk (str | Unset):  Default: 'low'.
        is_oss (bool | Unset):  Default: True.
        has_vulnerabilities (bool | Unset):  Default: False.
        vuln_count (int | Unset):  Default: 0.
        approved (bool | Unset):  Default: False.
    """

    package_name: str
    org_id: str | Unset = "default"
    package_version: str | Unset = ""
    license_type: str | Unset = "unknown"
    license_risk: str | Unset = "low"
    is_oss: bool | Unset = True
    has_vulnerabilities: bool | Unset = False
    vuln_count: int | Unset = 0
    approved: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_name = self.package_name

        org_id = self.org_id

        package_version = self.package_version

        license_type = self.license_type

        license_risk = self.license_risk

        is_oss = self.is_oss

        has_vulnerabilities = self.has_vulnerabilities

        vuln_count = self.vuln_count

        approved = self.approved

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_name": package_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if package_version is not UNSET:
            field_dict["package_version"] = package_version
        if license_type is not UNSET:
            field_dict["license_type"] = license_type
        if license_risk is not UNSET:
            field_dict["license_risk"] = license_risk
        if is_oss is not UNSET:
            field_dict["is_oss"] = is_oss
        if has_vulnerabilities is not UNSET:
            field_dict["has_vulnerabilities"] = has_vulnerabilities
        if vuln_count is not UNSET:
            field_dict["vuln_count"] = vuln_count
        if approved is not UNSET:
            field_dict["approved"] = approved

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package_name = d.pop("package_name")

        org_id = d.pop("org_id", UNSET)

        package_version = d.pop("package_version", UNSET)

        license_type = d.pop("license_type", UNSET)

        license_risk = d.pop("license_risk", UNSET)

        is_oss = d.pop("is_oss", UNSET)

        has_vulnerabilities = d.pop("has_vulnerabilities", UNSET)

        vuln_count = d.pop("vuln_count", UNSET)

        approved = d.pop("approved", UNSET)

        add_license_record_request = cls(
            package_name=package_name,
            org_id=org_id,
            package_version=package_version,
            license_type=license_type,
            license_risk=license_risk,
            is_oss=is_oss,
            has_vulnerabilities=has_vulnerabilities,
            vuln_count=vuln_count,
            approved=approved,
        )

        add_license_record_request.additional_properties = d
        return add_license_record_request

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
