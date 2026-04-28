from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.vuln_analysis_response_impact_analysis import VulnAnalysisResponseImpactAnalysis
    from ..models.vuln_analysis_response_threat_intel import VulnAnalysisResponseThreatIntel


T = TypeVar("T", bound="VulnAnalysisResponse")


@_attrs_define
class VulnAnalysisResponse:
    """Vulnerability analysis result.

    Attributes:
        cve_id (None | str):
        severity (str):
        epss_score (float):
        epss_percentile (float):
        kev_listed (bool):
        threat_intel (VulnAnalysisResponseThreatIntel):
        attack_vector (str):
        impact_analysis (VulnAnalysisResponseImpactAnalysis):
        recommendation (str):
        first_seen (datetime.datetime | None | Unset):
    """

    cve_id: None | str
    severity: str
    epss_score: float
    epss_percentile: float
    kev_listed: bool
    threat_intel: VulnAnalysisResponseThreatIntel
    attack_vector: str
    impact_analysis: VulnAnalysisResponseImpactAnalysis
    recommendation: str
    first_seen: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id: None | str
        cve_id = self.cve_id

        severity = self.severity

        epss_score = self.epss_score

        epss_percentile = self.epss_percentile

        kev_listed = self.kev_listed

        threat_intel = self.threat_intel.to_dict()

        attack_vector = self.attack_vector

        impact_analysis = self.impact_analysis.to_dict()

        recommendation = self.recommendation

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        elif isinstance(self.first_seen, datetime.datetime):
            first_seen = self.first_seen.isoformat()
        else:
            first_seen = self.first_seen

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "severity": severity,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "kev_listed": kev_listed,
                "threat_intel": threat_intel,
                "attack_vector": attack_vector,
                "impact_analysis": impact_analysis,
                "recommendation": recommendation,
            }
        )
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_analysis_response_impact_analysis import VulnAnalysisResponseImpactAnalysis
        from ..models.vuln_analysis_response_threat_intel import VulnAnalysisResponseThreatIntel

        d = dict(src_dict)

        def _parse_cve_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        cve_id = _parse_cve_id(d.pop("cve_id"))

        severity = d.pop("severity")

        epss_score = d.pop("epss_score")

        epss_percentile = d.pop("epss_percentile")

        kev_listed = d.pop("kev_listed")

        threat_intel = VulnAnalysisResponseThreatIntel.from_dict(d.pop("threat_intel"))

        attack_vector = d.pop("attack_vector")

        impact_analysis = VulnAnalysisResponseImpactAnalysis.from_dict(d.pop("impact_analysis"))

        recommendation = d.pop("recommendation")

        def _parse_first_seen(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                first_seen_type_0 = isoparse(data)

                return first_seen_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        vuln_analysis_response = cls(
            cve_id=cve_id,
            severity=severity,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            kev_listed=kev_listed,
            threat_intel=threat_intel,
            attack_vector=attack_vector,
            impact_analysis=impact_analysis,
            recommendation=recommendation,
            first_seen=first_seen,
        )

        vuln_analysis_response.additional_properties = d
        return vuln_analysis_response

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
