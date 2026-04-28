from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnalysisCreate")


@_attrs_define
class AnalysisCreate:
    """
    Attributes:
        analysis_type (str | Unset):  Default: 'static'.
        analyst (str | Unset):  Default: ''.
        findings (str | Unset):  Default: ''.
        iocs_found (list[Any] | Unset):
        malware_families (list[Any] | Unset):
        risk_score (float | Unset):  Default: 0.0.
        recommendations (str | Unset):  Default: ''.
    """

    analysis_type: str | Unset = "static"
    analyst: str | Unset = ""
    findings: str | Unset = ""
    iocs_found: list[Any] | Unset = UNSET
    malware_families: list[Any] | Unset = UNSET
    risk_score: float | Unset = 0.0
    recommendations: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        analysis_type = self.analysis_type

        analyst = self.analyst

        findings = self.findings

        iocs_found: list[Any] | Unset = UNSET
        if not isinstance(self.iocs_found, Unset):
            iocs_found = self.iocs_found

        malware_families: list[Any] | Unset = UNSET
        if not isinstance(self.malware_families, Unset):
            malware_families = self.malware_families

        risk_score = self.risk_score

        recommendations = self.recommendations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if analysis_type is not UNSET:
            field_dict["analysis_type"] = analysis_type
        if analyst is not UNSET:
            field_dict["analyst"] = analyst
        if findings is not UNSET:
            field_dict["findings"] = findings
        if iocs_found is not UNSET:
            field_dict["iocs_found"] = iocs_found
        if malware_families is not UNSET:
            field_dict["malware_families"] = malware_families
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if recommendations is not UNSET:
            field_dict["recommendations"] = recommendations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        analysis_type = d.pop("analysis_type", UNSET)

        analyst = d.pop("analyst", UNSET)

        findings = d.pop("findings", UNSET)

        iocs_found = cast(list[Any], d.pop("iocs_found", UNSET))

        malware_families = cast(list[Any], d.pop("malware_families", UNSET))

        risk_score = d.pop("risk_score", UNSET)

        recommendations = d.pop("recommendations", UNSET)

        analysis_create = cls(
            analysis_type=analysis_type,
            analyst=analyst,
            findings=findings,
            iocs_found=iocs_found,
            malware_families=malware_families,
            risk_score=risk_score,
            recommendations=recommendations,
        )

        analysis_create.additional_properties = d
        return analysis_create

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
