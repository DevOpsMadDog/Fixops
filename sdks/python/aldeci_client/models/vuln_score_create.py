from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VulnScoreCreate")


@_attrs_define
class VulnScoreCreate:
    """
    Attributes:
        cve_id (str):
        asset_id (str):
        asset_criticality (str | Unset):  Default: 'medium'.
        cvss_score (float | Unset):  Default: 0.0.
        epss_score (float | Unset):  Default: 0.0.
        kev_listed (bool | Unset):  Default: False.
        exploitability (str | Unset):  Default: 'theoretical'.
        exposure (str | Unset):  Default: 'internal'.
    """

    cve_id: str
    asset_id: str
    asset_criticality: str | Unset = "medium"
    cvss_score: float | Unset = 0.0
    epss_score: float | Unset = 0.0
    kev_listed: bool | Unset = False
    exploitability: str | Unset = "theoretical"
    exposure: str | Unset = "internal"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        asset_id = self.asset_id

        asset_criticality = self.asset_criticality

        cvss_score = self.cvss_score

        epss_score = self.epss_score

        kev_listed = self.kev_listed

        exploitability = self.exploitability

        exposure = self.exposure

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "asset_id": asset_id,
            }
        )
        if asset_criticality is not UNSET:
            field_dict["asset_criticality"] = asset_criticality
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if kev_listed is not UNSET:
            field_dict["kev_listed"] = kev_listed
        if exploitability is not UNSET:
            field_dict["exploitability"] = exploitability
        if exposure is not UNSET:
            field_dict["exposure"] = exposure

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        asset_id = d.pop("asset_id")

        asset_criticality = d.pop("asset_criticality", UNSET)

        cvss_score = d.pop("cvss_score", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        kev_listed = d.pop("kev_listed", UNSET)

        exploitability = d.pop("exploitability", UNSET)

        exposure = d.pop("exposure", UNSET)

        vuln_score_create = cls(
            cve_id=cve_id,
            asset_id=asset_id,
            asset_criticality=asset_criticality,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_listed=kev_listed,
            exploitability=exploitability,
            exposure=exposure,
        )

        vuln_score_create.additional_properties = d
        return vuln_score_create

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
