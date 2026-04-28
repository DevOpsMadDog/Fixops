from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CVERiskRequest")


@_attrs_define
class CVERiskRequest:
    """Request for CVE-based risk quantification.

    Attributes:
        cve_id (str): CVE identifier
        cvss_score (float | Unset): CVSS score (default 5.0 if unknown) Default: 5.0.
        epss_score (float | Unset): EPSS score (0-1) Default: 0.0.
        kev_listed (bool | Unset): Whether in CISA KEV catalog Default: False.
        asset_value (float | Unset): Asset value in dollars Default: 100000.0.
        is_reachable (bool | Unset): Whether vulnerable code is reachable Default: True.
        simulations (int | Unset): Number of simulations Default: 10000.
    """

    cve_id: str
    cvss_score: float | Unset = 5.0
    epss_score: float | Unset = 0.0
    kev_listed: bool | Unset = False
    asset_value: float | Unset = 100000.0
    is_reachable: bool | Unset = True
    simulations: int | Unset = 10000
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        cvss_score = self.cvss_score

        epss_score = self.epss_score

        kev_listed = self.kev_listed

        asset_value = self.asset_value

        is_reachable = self.is_reachable

        simulations = self.simulations

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
        if kev_listed is not UNSET:
            field_dict["kev_listed"] = kev_listed
        if asset_value is not UNSET:
            field_dict["asset_value"] = asset_value
        if is_reachable is not UNSET:
            field_dict["is_reachable"] = is_reachable
        if simulations is not UNSET:
            field_dict["simulations"] = simulations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        cvss_score = d.pop("cvss_score", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        kev_listed = d.pop("kev_listed", UNSET)

        asset_value = d.pop("asset_value", UNSET)

        is_reachable = d.pop("is_reachable", UNSET)

        simulations = d.pop("simulations", UNSET)

        cve_risk_request = cls(
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_listed=kev_listed,
            asset_value=asset_value,
            is_reachable=is_reachable,
            simulations=simulations,
        )

        cve_risk_request.additional_properties = d
        return cve_risk_request

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
