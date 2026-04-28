from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssignVulnIn")


@_attrs_define
class AssignVulnIn:
    """
    Attributes:
        asset_id (str): Asset ID
        cve_id (str): CVE identifier e.g. CVE-2024-1234
        cvss_score (float | Unset): CVSS score 0-10 Default: 0.0.
        epss_score (float | Unset): EPSS probability 0-1 Default: 0.0.
        kev_listed (bool | Unset): Whether in CISA KEV catalog Default: False.
        exploitability (str | Unset): low|medium|high|critical Default: 'low'.
        patch_status (str | Unset): unpatched|partial|patched Default: 'unpatched'.
        priority (str | Unset): immediate|high|medium|low|scheduled Default: 'medium'.
    """

    asset_id: str
    cve_id: str
    cvss_score: float | Unset = 0.0
    epss_score: float | Unset = 0.0
    kev_listed: bool | Unset = False
    exploitability: str | Unset = "low"
    patch_status: str | Unset = "unpatched"
    priority: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        cve_id = self.cve_id

        cvss_score = self.cvss_score

        epss_score = self.epss_score

        kev_listed = self.kev_listed

        exploitability = self.exploitability

        patch_status = self.patch_status

        priority = self.priority

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
                "cve_id": cve_id,
            }
        )
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if kev_listed is not UNSET:
            field_dict["kev_listed"] = kev_listed
        if exploitability is not UNSET:
            field_dict["exploitability"] = exploitability
        if patch_status is not UNSET:
            field_dict["patch_status"] = patch_status
        if priority is not UNSET:
            field_dict["priority"] = priority

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        cve_id = d.pop("cve_id")

        cvss_score = d.pop("cvss_score", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        kev_listed = d.pop("kev_listed", UNSET)

        exploitability = d.pop("exploitability", UNSET)

        patch_status = d.pop("patch_status", UNSET)

        priority = d.pop("priority", UNSET)

        assign_vuln_in = cls(
            asset_id=asset_id,
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_listed=kev_listed,
            exploitability=exploitability,
            patch_status=patch_status,
            priority=priority,
        )

        assign_vuln_in.additional_properties = d
        return assign_vuln_in

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
