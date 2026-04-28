from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScoreRequest")


@_attrs_define
class ScoreRequest:
    """
    Attributes:
        cve_id (str): CVE identifier, e.g. CVE-2021-44228
        cvss_score (float | Unset): CVSS base score 0-10 Default: 0.0.
        epss_score (float | Unset): EPSS probability 0-1 Default: 0.0.
        asset_criticality (str | Unset): Asset criticality: low|medium|high|critical Default: 'medium'.
    """

    cve_id: str
    cvss_score: float | Unset = 0.0
    epss_score: float | Unset = 0.0
    asset_criticality: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        cvss_score = self.cvss_score

        epss_score = self.epss_score

        asset_criticality = self.asset_criticality

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if asset_criticality is not UNSET:
            field_dict["asset_criticality"] = asset_criticality

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        cvss_score = d.pop("cvss_score", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        asset_criticality = d.pop("asset_criticality", UNSET)

        score_request = cls(
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            asset_criticality=asset_criticality,
        )

        score_request.additional_properties = d
        return score_request

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
