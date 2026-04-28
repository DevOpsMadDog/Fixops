from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="EngineScorecardResponse")


@_attrs_define
class EngineScorecardResponse:
    """Engine-generated vendor scorecard.

    Attributes:
        vendor_id (str):
        vendor_name (str):
        overall_score (float):
        risk_level (str):
        grade (str):
        domain_score (float):
        cve_score (float):
        breach_score (float):
        data_handling_score (float):
        fourth_party_score (float):
        findings_count (int):
        critical_findings (int):
        calculated_at (str):
        recommendations (list[str]):
    """

    vendor_id: str
    vendor_name: str
    overall_score: float
    risk_level: str
    grade: str
    domain_score: float
    cve_score: float
    breach_score: float
    data_handling_score: float
    fourth_party_score: float
    findings_count: int
    critical_findings: int
    calculated_at: str
    recommendations: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor_id = self.vendor_id

        vendor_name = self.vendor_name

        overall_score = self.overall_score

        risk_level = self.risk_level

        grade = self.grade

        domain_score = self.domain_score

        cve_score = self.cve_score

        breach_score = self.breach_score

        data_handling_score = self.data_handling_score

        fourth_party_score = self.fourth_party_score

        findings_count = self.findings_count

        critical_findings = self.critical_findings

        calculated_at = self.calculated_at

        recommendations = self.recommendations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor_id": vendor_id,
                "vendor_name": vendor_name,
                "overall_score": overall_score,
                "risk_level": risk_level,
                "grade": grade,
                "domain_score": domain_score,
                "cve_score": cve_score,
                "breach_score": breach_score,
                "data_handling_score": data_handling_score,
                "fourth_party_score": fourth_party_score,
                "findings_count": findings_count,
                "critical_findings": critical_findings,
                "calculated_at": calculated_at,
                "recommendations": recommendations,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vendor_id = d.pop("vendor_id")

        vendor_name = d.pop("vendor_name")

        overall_score = d.pop("overall_score")

        risk_level = d.pop("risk_level")

        grade = d.pop("grade")

        domain_score = d.pop("domain_score")

        cve_score = d.pop("cve_score")

        breach_score = d.pop("breach_score")

        data_handling_score = d.pop("data_handling_score")

        fourth_party_score = d.pop("fourth_party_score")

        findings_count = d.pop("findings_count")

        critical_findings = d.pop("critical_findings")

        calculated_at = d.pop("calculated_at")

        recommendations = cast(list[str], d.pop("recommendations"))

        engine_scorecard_response = cls(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            overall_score=overall_score,
            risk_level=risk_level,
            grade=grade,
            domain_score=domain_score,
            cve_score=cve_score,
            breach_score=breach_score,
            data_handling_score=data_handling_score,
            fourth_party_score=fourth_party_score,
            findings_count=findings_count,
            critical_findings=critical_findings,
            calculated_at=calculated_at,
            recommendations=recommendations,
        )

        engine_scorecard_response.additional_properties = d
        return engine_scorecard_response

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
