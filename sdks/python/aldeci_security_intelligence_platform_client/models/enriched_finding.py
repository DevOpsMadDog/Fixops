from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.enriched_finding_epss_scores import EnrichedFindingEpssScores
    from ..models.enriched_finding_original_finding import EnrichedFindingOriginalFinding


T = TypeVar("T", bound="EnrichedFinding")


@_attrs_define
class EnrichedFinding:
    """A raw scanner finding enriched with CVE intel, EPSS, KEV, and risk score.

    Attributes:
        original_finding (EnrichedFindingOriginalFinding): The raw finding dict as received from the scanner
        matched_cves (list[str] | Unset): CVE IDs matched via CWE mapping or scanner output
        epss_scores (EnrichedFindingEpssScores | Unset): EPSS probability per CVE (0.0–1.0)
        in_kev (bool | Unset): True if any matched CVE is in CISA KEV Default: False.
        kev_due_date (None | str | Unset): CISA KEV remediation due date (ISO-8601) for the highest-priority KEV CVE
        fix_guidance (str | Unset): Human-readable remediation guidance from NVD references Default: ''.
        composite_risk_score (float | Unset): Composite risk 0–100: (CVSS/10*40) + (EPSS*35) + (in_kev*25) Default: 0.0.
        enriched_at (str | Unset): ISO-8601 timestamp when enrichment was performed
    """

    original_finding: EnrichedFindingOriginalFinding
    matched_cves: list[str] | Unset = UNSET
    epss_scores: EnrichedFindingEpssScores | Unset = UNSET
    in_kev: bool | Unset = False
    kev_due_date: None | str | Unset = UNSET
    fix_guidance: str | Unset = ""
    composite_risk_score: float | Unset = 0.0
    enriched_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        original_finding = self.original_finding.to_dict()

        matched_cves: list[str] | Unset = UNSET
        if not isinstance(self.matched_cves, Unset):
            matched_cves = self.matched_cves

        epss_scores: dict[str, Any] | Unset = UNSET
        if not isinstance(self.epss_scores, Unset):
            epss_scores = self.epss_scores.to_dict()

        in_kev = self.in_kev

        kev_due_date: None | str | Unset
        if isinstance(self.kev_due_date, Unset):
            kev_due_date = UNSET
        else:
            kev_due_date = self.kev_due_date

        fix_guidance = self.fix_guidance

        composite_risk_score = self.composite_risk_score

        enriched_at = self.enriched_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "original_finding": original_finding,
            }
        )
        if matched_cves is not UNSET:
            field_dict["matched_cves"] = matched_cves
        if epss_scores is not UNSET:
            field_dict["epss_scores"] = epss_scores
        if in_kev is not UNSET:
            field_dict["in_kev"] = in_kev
        if kev_due_date is not UNSET:
            field_dict["kev_due_date"] = kev_due_date
        if fix_guidance is not UNSET:
            field_dict["fix_guidance"] = fix_guidance
        if composite_risk_score is not UNSET:
            field_dict["composite_risk_score"] = composite_risk_score
        if enriched_at is not UNSET:
            field_dict["enriched_at"] = enriched_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.enriched_finding_epss_scores import EnrichedFindingEpssScores
        from ..models.enriched_finding_original_finding import EnrichedFindingOriginalFinding

        d = dict(src_dict)
        original_finding = EnrichedFindingOriginalFinding.from_dict(d.pop("original_finding"))

        matched_cves = cast(list[str], d.pop("matched_cves", UNSET))

        _epss_scores = d.pop("epss_scores", UNSET)
        epss_scores: EnrichedFindingEpssScores | Unset
        if isinstance(_epss_scores, Unset):
            epss_scores = UNSET
        else:
            epss_scores = EnrichedFindingEpssScores.from_dict(_epss_scores)

        in_kev = d.pop("in_kev", UNSET)

        def _parse_kev_due_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_due_date = _parse_kev_due_date(d.pop("kev_due_date", UNSET))

        fix_guidance = d.pop("fix_guidance", UNSET)

        composite_risk_score = d.pop("composite_risk_score", UNSET)

        enriched_at = d.pop("enriched_at", UNSET)

        enriched_finding = cls(
            original_finding=original_finding,
            matched_cves=matched_cves,
            epss_scores=epss_scores,
            in_kev=in_kev,
            kev_due_date=kev_due_date,
            fix_guidance=fix_guidance,
            composite_risk_score=composite_risk_score,
            enriched_at=enriched_at,
        )

        enriched_finding.additional_properties = d
        return enriched_finding

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
