from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VulnTrack")


@_attrs_define
class VulnTrack:
    """
    Attributes:
        org_id (str):
        vuln_id (str):
        cve_id (str | Unset):  Default: ''.
        asset_id (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        cvss_score (float | Unset):  Default: 0.0.
        discovered_at (None | str | Unset):
    """

    org_id: str
    vuln_id: str
    cve_id: str | Unset = ""
    asset_id: str | Unset = ""
    severity: str | Unset = "medium"
    cvss_score: float | Unset = 0.0
    discovered_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        vuln_id = self.vuln_id

        cve_id = self.cve_id

        asset_id = self.asset_id

        severity = self.severity

        cvss_score = self.cvss_score

        discovered_at: None | str | Unset
        if isinstance(self.discovered_at, Unset):
            discovered_at = UNSET
        else:
            discovered_at = self.discovered_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "vuln_id": vuln_id,
            }
        )
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if discovered_at is not UNSET:
            field_dict["discovered_at"] = discovered_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        vuln_id = d.pop("vuln_id")

        cve_id = d.pop("cve_id", UNSET)

        asset_id = d.pop("asset_id", UNSET)

        severity = d.pop("severity", UNSET)

        cvss_score = d.pop("cvss_score", UNSET)

        def _parse_discovered_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        discovered_at = _parse_discovered_at(d.pop("discovered_at", UNSET))

        vuln_track = cls(
            org_id=org_id,
            vuln_id=vuln_id,
            cve_id=cve_id,
            asset_id=asset_id,
            severity=severity,
            cvss_score=cvss_score,
            discovered_at=discovered_at,
        )

        vuln_track.additional_properties = d
        return vuln_track

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
