from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.auto_assess_response_breach_matches_item import AutoAssessResponseBreachMatchesItem
    from ..models.auto_assess_response_cves_item import AutoAssessResponseCvesItem
    from ..models.auto_assess_response_findings_item import AutoAssessResponseFindingsItem


T = TypeVar("T", bound="AutoAssessResponse")


@_attrs_define
class AutoAssessResponse:
    """Automated vendor risk assessment result.

    Attributes:
        vendor_id (str):
        name (str):
        domain (None | str):
        risk_score (float):
        risk_level (str):
        findings (list[AutoAssessResponseFindingsItem]):
        last_assessed (str):
        recommendations (list[str]):
        cves (list[AutoAssessResponseCvesItem]):
        breach_matches (list[AutoAssessResponseBreachMatchesItem]):
    """

    vendor_id: str
    name: str
    domain: None | str
    risk_score: float
    risk_level: str
    findings: list[AutoAssessResponseFindingsItem]
    last_assessed: str
    recommendations: list[str]
    cves: list[AutoAssessResponseCvesItem]
    breach_matches: list[AutoAssessResponseBreachMatchesItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor_id = self.vendor_id

        name = self.name

        domain: None | str
        domain = self.domain

        risk_score = self.risk_score

        risk_level = self.risk_level

        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        last_assessed = self.last_assessed

        recommendations = self.recommendations

        cves = []
        for cves_item_data in self.cves:
            cves_item = cves_item_data.to_dict()
            cves.append(cves_item)

        breach_matches = []
        for breach_matches_item_data in self.breach_matches:
            breach_matches_item = breach_matches_item_data.to_dict()
            breach_matches.append(breach_matches_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor_id": vendor_id,
                "name": name,
                "domain": domain,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "findings": findings,
                "last_assessed": last_assessed,
                "recommendations": recommendations,
                "cves": cves,
                "breach_matches": breach_matches,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auto_assess_response_breach_matches_item import AutoAssessResponseBreachMatchesItem
        from ..models.auto_assess_response_cves_item import AutoAssessResponseCvesItem
        from ..models.auto_assess_response_findings_item import AutoAssessResponseFindingsItem

        d = dict(src_dict)
        vendor_id = d.pop("vendor_id")

        name = d.pop("name")

        def _parse_domain(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        domain = _parse_domain(d.pop("domain"))

        risk_score = d.pop("risk_score")

        risk_level = d.pop("risk_level")

        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = AutoAssessResponseFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        last_assessed = d.pop("last_assessed")

        recommendations = cast(list[str], d.pop("recommendations"))

        cves = []
        _cves = d.pop("cves")
        for cves_item_data in _cves:
            cves_item = AutoAssessResponseCvesItem.from_dict(cves_item_data)

            cves.append(cves_item)

        breach_matches = []
        _breach_matches = d.pop("breach_matches")
        for breach_matches_item_data in _breach_matches:
            breach_matches_item = AutoAssessResponseBreachMatchesItem.from_dict(breach_matches_item_data)

            breach_matches.append(breach_matches_item)

        auto_assess_response = cls(
            vendor_id=vendor_id,
            name=name,
            domain=domain,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            last_assessed=last_assessed,
            recommendations=recommendations,
            cves=cves,
            breach_matches=breach_matches,
        )

        auto_assess_response.additional_properties = d
        return auto_assess_response

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
