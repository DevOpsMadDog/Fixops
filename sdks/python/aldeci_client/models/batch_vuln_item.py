from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchVulnItem")


@_attrs_define
class BatchVulnItem:
    """
    Attributes:
        cve_id (str):
        asset_criticality (str | Unset):  Default: 'medium'.
        internet_exposed (bool | Unset):  Default: False.
        has_known_exploit (bool | Unset):  Default: False.
        epss_score (float | Unset):  Default: 0.0.
        cvss_base (float | Unset):  Default: 0.0.
        kev (bool | Unset):  Default: False.
    """

    cve_id: str
    asset_criticality: str | Unset = "medium"
    internet_exposed: bool | Unset = False
    has_known_exploit: bool | Unset = False
    epss_score: float | Unset = 0.0
    cvss_base: float | Unset = 0.0
    kev: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        asset_criticality = self.asset_criticality

        internet_exposed = self.internet_exposed

        has_known_exploit = self.has_known_exploit

        epss_score = self.epss_score

        cvss_base = self.cvss_base

        kev = self.kev

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if asset_criticality is not UNSET:
            field_dict["asset_criticality"] = asset_criticality
        if internet_exposed is not UNSET:
            field_dict["internet_exposed"] = internet_exposed
        if has_known_exploit is not UNSET:
            field_dict["has_known_exploit"] = has_known_exploit
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if cvss_base is not UNSET:
            field_dict["cvss_base"] = cvss_base
        if kev is not UNSET:
            field_dict["kev"] = kev

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        asset_criticality = d.pop("asset_criticality", UNSET)

        internet_exposed = d.pop("internet_exposed", UNSET)

        has_known_exploit = d.pop("has_known_exploit", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        cvss_base = d.pop("cvss_base", UNSET)

        kev = d.pop("kev", UNSET)

        batch_vuln_item = cls(
            cve_id=cve_id,
            asset_criticality=asset_criticality,
            internet_exposed=internet_exposed,
            has_known_exploit=has_known_exploit,
            epss_score=epss_score,
            cvss_base=cvss_base,
            kev=kev,
        )

        batch_vuln_item.additional_properties = d
        return batch_vuln_item

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
