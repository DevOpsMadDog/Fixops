from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.vuln_severity import VulnSeverity
from ..models.vuln_status import VulnStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="DiscoveredVulnResponse")


@_attrs_define
class DiscoveredVulnResponse:
    """Response for discovered vulnerability.

    Attributes:
        id (str):
        internal_id (str):
        title (str):
        severity (VulnSeverity): Vulnerability severity levels.
        status (VulnStatus): Vulnerability disclosure status.
        created_at (datetime.datetime):
        discovered_by (str):
        cvss_score (float | None | Unset):
        cve_id (None | str | Unset):
    """

    id: str
    internal_id: str
    title: str
    severity: VulnSeverity
    status: VulnStatus
    created_at: datetime.datetime
    discovered_by: str
    cvss_score: float | None | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        internal_id = self.internal_id

        title = self.title

        severity = self.severity.value

        status = self.status.value

        created_at = self.created_at.isoformat()

        discovered_by = self.discovered_by

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "internal_id": internal_id,
                "title": title,
                "severity": severity,
                "status": status,
                "created_at": created_at,
                "discovered_by": discovered_by,
            }
        )
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        internal_id = d.pop("internal_id")

        title = d.pop("title")

        severity = VulnSeverity(d.pop("severity"))

        status = VulnStatus(d.pop("status"))

        created_at = isoparse(d.pop("created_at"))

        discovered_by = d.pop("discovered_by")

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        discovered_vuln_response = cls(
            id=id,
            internal_id=internal_id,
            title=title,
            severity=severity,
            status=status,
            created_at=created_at,
            discovered_by=discovered_by,
            cvss_score=cvss_score,
            cve_id=cve_id,
        )

        discovered_vuln_response.additional_properties = d
        return discovered_vuln_response

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
