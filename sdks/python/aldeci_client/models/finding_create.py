from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.finding_severity import FindingSeverity
from ..models.finding_status import FindingStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.finding_create_metadata import FindingCreateMetadata


T = TypeVar("T", bound="FindingCreate")


@_attrs_define
class FindingCreate:
    """Request model for creating a finding.

    Attributes:
        org_id (str): Organization ID for multi-tenancy
        rule_id (str):
        severity (FindingSeverity): Finding severity levels.
        title (str):
        description (str):
        source (str):
        application_id (None | str | Unset):
        service_id (None | str | Unset):
        status (FindingStatus | Unset): Finding status.
        cve_id (None | str | Unset):
        cvss_score (float | None | Unset):
        epss_score (float | None | Unset):
        exploitable (bool | Unset):  Default: False.
        metadata (FindingCreateMetadata | Unset):
    """

    org_id: str
    rule_id: str
    severity: FindingSeverity
    title: str
    description: str
    source: str
    application_id: None | str | Unset = UNSET
    service_id: None | str | Unset = UNSET
    status: FindingStatus | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    cvss_score: float | None | Unset = UNSET
    epss_score: float | None | Unset = UNSET
    exploitable: bool | Unset = False
    metadata: FindingCreateMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        rule_id = self.rule_id

        severity = self.severity.value

        title = self.title

        description = self.description

        source = self.source

        application_id: None | str | Unset
        if isinstance(self.application_id, Unset):
            application_id = UNSET
        else:
            application_id = self.application_id

        service_id: None | str | Unset
        if isinstance(self.service_id, Unset):
            service_id = UNSET
        else:
            service_id = self.service_id

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        epss_score: float | None | Unset
        if isinstance(self.epss_score, Unset):
            epss_score = UNSET
        else:
            epss_score = self.epss_score

        exploitable = self.exploitable

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
                "description": description,
                "source": source,
            }
        )
        if application_id is not UNSET:
            field_dict["application_id"] = application_id
        if service_id is not UNSET:
            field_dict["service_id"] = service_id
        if status is not UNSET:
            field_dict["status"] = status
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if exploitable is not UNSET:
            field_dict["exploitable"] = exploitable
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_create_metadata import FindingCreateMetadata

        d = dict(src_dict)
        org_id = d.pop("org_id")

        rule_id = d.pop("rule_id")

        severity = FindingSeverity(d.pop("severity"))

        title = d.pop("title")

        description = d.pop("description")

        source = d.pop("source")

        def _parse_application_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        application_id = _parse_application_id(d.pop("application_id", UNSET))

        def _parse_service_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        service_id = _parse_service_id(d.pop("service_id", UNSET))

        _status = d.pop("status", UNSET)
        status: FindingStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = FindingStatus(_status)

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_epss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_score = _parse_epss_score(d.pop("epss_score", UNSET))

        exploitable = d.pop("exploitable", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: FindingCreateMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = FindingCreateMetadata.from_dict(_metadata)

        finding_create = cls(
            org_id=org_id,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            source=source,
            application_id=application_id,
            service_id=service_id,
            status=status,
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            exploitable=exploitable,
            metadata=metadata,
        )

        finding_create.additional_properties = d
        return finding_create

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
