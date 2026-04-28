from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

T = TypeVar("T", bound="DueDiligenceResponse")


@_attrs_define
class DueDiligenceResponse:
    """M&A due diligence security report.

    Attributes:
        org_id (str):
        security_debt_usd (float):
        compliance_readiness_pct (float):
        critical_vuln_count (int):
        high_vuln_count (int):
        time_to_remediation_days (int):
        insurance_premium_impact_usd (float):
        risk_rating (str):
        findings_summary (list[str]):
        computed_at (datetime.datetime):
    """

    org_id: str
    security_debt_usd: float
    compliance_readiness_pct: float
    critical_vuln_count: int
    high_vuln_count: int
    time_to_remediation_days: int
    insurance_premium_impact_usd: float
    risk_rating: str
    findings_summary: list[str]
    computed_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        security_debt_usd = self.security_debt_usd

        compliance_readiness_pct = self.compliance_readiness_pct

        critical_vuln_count = self.critical_vuln_count

        high_vuln_count = self.high_vuln_count

        time_to_remediation_days = self.time_to_remediation_days

        insurance_premium_impact_usd = self.insurance_premium_impact_usd

        risk_rating = self.risk_rating

        findings_summary = self.findings_summary

        computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "security_debt_usd": security_debt_usd,
                "compliance_readiness_pct": compliance_readiness_pct,
                "critical_vuln_count": critical_vuln_count,
                "high_vuln_count": high_vuln_count,
                "time_to_remediation_days": time_to_remediation_days,
                "insurance_premium_impact_usd": insurance_premium_impact_usd,
                "risk_rating": risk_rating,
                "findings_summary": findings_summary,
                "computed_at": computed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        security_debt_usd = d.pop("security_debt_usd")

        compliance_readiness_pct = d.pop("compliance_readiness_pct")

        critical_vuln_count = d.pop("critical_vuln_count")

        high_vuln_count = d.pop("high_vuln_count")

        time_to_remediation_days = d.pop("time_to_remediation_days")

        insurance_premium_impact_usd = d.pop("insurance_premium_impact_usd")

        risk_rating = d.pop("risk_rating")

        findings_summary = cast(list[str], d.pop("findings_summary"))

        computed_at = isoparse(d.pop("computed_at"))

        due_diligence_response = cls(
            org_id=org_id,
            security_debt_usd=security_debt_usd,
            compliance_readiness_pct=compliance_readiness_pct,
            critical_vuln_count=critical_vuln_count,
            high_vuln_count=high_vuln_count,
            time_to_remediation_days=time_to_remediation_days,
            insurance_premium_impact_usd=insurance_premium_impact_usd,
            risk_rating=risk_rating,
            findings_summary=findings_summary,
            computed_at=computed_at,
        )

        due_diligence_response.additional_properties = d
        return due_diligence_response

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
