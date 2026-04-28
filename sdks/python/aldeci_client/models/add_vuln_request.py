from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddVulnRequest")


@_attrs_define
class AddVulnRequest:
    """
    Attributes:
        org_id (str): Organisation ID
        cve_id (str): CVE identifier
        severity (str): critical|high|medium|low|informational
        cvss_score (float | Unset): CVSS score Default: 0.0.
        affects_version (str | Unset): Affected version string Default: ''.
        fixed_in (str | Unset): Version where fix is available Default: ''.
    """

    org_id: str
    cve_id: str
    severity: str
    cvss_score: float | Unset = 0.0
    affects_version: str | Unset = ""
    fixed_in: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        cve_id = self.cve_id

        severity = self.severity

        cvss_score = self.cvss_score

        affects_version = self.affects_version

        fixed_in = self.fixed_in

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "cve_id": cve_id,
                "severity": severity,
            }
        )
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if affects_version is not UNSET:
            field_dict["affects_version"] = affects_version
        if fixed_in is not UNSET:
            field_dict["fixed_in"] = fixed_in

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        cve_id = d.pop("cve_id")

        severity = d.pop("severity")

        cvss_score = d.pop("cvss_score", UNSET)

        affects_version = d.pop("affects_version", UNSET)

        fixed_in = d.pop("fixed_in", UNSET)

        add_vuln_request = cls(
            org_id=org_id,
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            affects_version=affects_version,
            fixed_in=fixed_in,
        )

        add_vuln_request.additional_properties = d
        return add_vuln_request

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
