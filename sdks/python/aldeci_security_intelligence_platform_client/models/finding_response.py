from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.finding_response_metadata import FindingResponseMetadata


T = TypeVar("T", bound="FindingResponse")


@_attrs_define
class FindingResponse:
    """Response model for a finding.

    Attributes:
        id (str):
        application_id (None | str):
        service_id (None | str):
        rule_id (str):
        severity (str):
        status (str):
        title (str):
        description (str):
        source (str):
        cve_id (None | str):
        cvss_score (float | None):
        epss_score (float | None):
        exploitable (bool):
        metadata (FindingResponseMetadata):
        created_at (str):
        updated_at (str):
        resolved_at (None | str):
        org_id (None | str | Unset):
    """

    id: str
    application_id: None | str
    service_id: None | str
    rule_id: str
    severity: str
    status: str
    title: str
    description: str
    source: str
    cve_id: None | str
    cvss_score: float | None
    epss_score: float | None
    exploitable: bool
    metadata: FindingResponseMetadata
    created_at: str
    updated_at: str
    resolved_at: None | str
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        application_id: None | str
        application_id = self.application_id

        service_id: None | str
        service_id = self.service_id

        rule_id = self.rule_id

        severity = self.severity

        status = self.status

        title = self.title

        description = self.description

        source = self.source

        cve_id: None | str
        cve_id = self.cve_id

        cvss_score: float | None
        cvss_score = self.cvss_score

        epss_score: float | None
        epss_score = self.epss_score

        exploitable = self.exploitable

        metadata = self.metadata.to_dict()

        created_at = self.created_at

        updated_at = self.updated_at

        resolved_at: None | str
        resolved_at = self.resolved_at

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "application_id": application_id,
                "service_id": service_id,
                "rule_id": rule_id,
                "severity": severity,
                "status": status,
                "title": title,
                "description": description,
                "source": source,
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "exploitable": exploitable,
                "metadata": metadata,
                "created_at": created_at,
                "updated_at": updated_at,
                "resolved_at": resolved_at,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_response_metadata import FindingResponseMetadata

        d = dict(src_dict)
        id = d.pop("id")

        def _parse_application_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        application_id = _parse_application_id(d.pop("application_id"))

        def _parse_service_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        service_id = _parse_service_id(d.pop("service_id"))

        rule_id = d.pop("rule_id")

        severity = d.pop("severity")

        status = d.pop("status")

        title = d.pop("title")

        description = d.pop("description")

        source = d.pop("source")

        def _parse_cve_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        cve_id = _parse_cve_id(d.pop("cve_id"))

        def _parse_cvss_score(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score"))

        def _parse_epss_score(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        epss_score = _parse_epss_score(d.pop("epss_score"))

        exploitable = d.pop("exploitable")

        metadata = FindingResponseMetadata.from_dict(d.pop("metadata"))

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        def _parse_resolved_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        resolved_at = _parse_resolved_at(d.pop("resolved_at"))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        finding_response = cls(
            id=id,
            application_id=application_id,
            service_id=service_id,
            rule_id=rule_id,
            severity=severity,
            status=status,
            title=title,
            description=description,
            source=source,
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            exploitable=exploitable,
            metadata=metadata,
            created_at=created_at,
            updated_at=updated_at,
            resolved_at=resolved_at,
            org_id=org_id,
        )

        finding_response.additional_properties = d
        return finding_response

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
