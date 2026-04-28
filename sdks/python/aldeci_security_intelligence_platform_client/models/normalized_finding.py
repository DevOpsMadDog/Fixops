from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.finding_severity import FindingSeverity
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.normalized_finding_metadata import NormalizedFindingMetadata


T = TypeVar("T", bound="NormalizedFinding")


@_attrs_define
class NormalizedFinding:
    """A finding normalized to ALDECI's canonical format.

    Attributes:
        finding_id (str): Unique ID from source system
        title (str): Finding title/summary
        severity (FindingSeverity): Finding severity levels.
        description (None | str | Unset): Detailed description
        cvss_score (float | None | Unset): CVSS v3 score
        cvss_vector (None | str | Unset): CVSS v3 vector string
        cve_ids (list[str] | Unset): CVE IDs (e.g. CVE-2024-1234)
        cwe_ids (list[int] | Unset): CWE IDs (e.g. 79, 89)
        component (None | str | Unset): Affected component/library
        version (None | str | Unset): Component version
        file_path (None | str | Unset): File path in repository
        line_number (int | None | Unset): Line number (if applicable)
        remediation (None | str | Unset): Remediation guidance
        remediation_effort (None | str | Unset): Estimated effort to fix
        false_positive (bool | Unset): Mark as false positive Default: False.
        tags (list[str] | Unset): Arbitrary tags
        metadata (NormalizedFindingMetadata | Unset): Additional metadata
    """

    finding_id: str
    title: str
    severity: FindingSeverity
    description: None | str | Unset = UNSET
    cvss_score: float | None | Unset = UNSET
    cvss_vector: None | str | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    cwe_ids: list[int] | Unset = UNSET
    component: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    file_path: None | str | Unset = UNSET
    line_number: int | None | Unset = UNSET
    remediation: None | str | Unset = UNSET
    remediation_effort: None | str | Unset = UNSET
    false_positive: bool | Unset = False
    tags: list[str] | Unset = UNSET
    metadata: NormalizedFindingMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        title = self.title

        severity = self.severity.value

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        cvss_vector: None | str | Unset
        if isinstance(self.cvss_vector, Unset):
            cvss_vector = UNSET
        else:
            cvss_vector = self.cvss_vector

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        cwe_ids: list[int] | Unset = UNSET
        if not isinstance(self.cwe_ids, Unset):
            cwe_ids = self.cwe_ids

        component: None | str | Unset
        if isinstance(self.component, Unset):
            component = UNSET
        else:
            component = self.component

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        file_path: None | str | Unset
        if isinstance(self.file_path, Unset):
            file_path = UNSET
        else:
            file_path = self.file_path

        line_number: int | None | Unset
        if isinstance(self.line_number, Unset):
            line_number = UNSET
        else:
            line_number = self.line_number

        remediation: None | str | Unset
        if isinstance(self.remediation, Unset):
            remediation = UNSET
        else:
            remediation = self.remediation

        remediation_effort: None | str | Unset
        if isinstance(self.remediation_effort, Unset):
            remediation_effort = UNSET
        else:
            remediation_effort = self.remediation_effort

        false_positive = self.false_positive

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "title": title,
                "severity": severity,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if cvss_vector is not UNSET:
            field_dict["cvss_vector"] = cvss_vector
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if component is not UNSET:
            field_dict["component"] = component
        if version is not UNSET:
            field_dict["version"] = version
        if file_path is not UNSET:
            field_dict["file_path"] = file_path
        if line_number is not UNSET:
            field_dict["line_number"] = line_number
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if remediation_effort is not UNSET:
            field_dict["remediation_effort"] = remediation_effort
        if false_positive is not UNSET:
            field_dict["false_positive"] = false_positive
        if tags is not UNSET:
            field_dict["tags"] = tags
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.normalized_finding_metadata import NormalizedFindingMetadata

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        title = d.pop("title")

        severity = FindingSeverity(d.pop("severity"))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_cvss_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_vector = _parse_cvss_vector(d.pop("cvss_vector", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        cwe_ids = cast(list[int], d.pop("cwe_ids", UNSET))

        def _parse_component(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        component = _parse_component(d.pop("component", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        def _parse_file_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        file_path = _parse_file_path(d.pop("file_path", UNSET))

        def _parse_line_number(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        line_number = _parse_line_number(d.pop("line_number", UNSET))

        def _parse_remediation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation = _parse_remediation(d.pop("remediation", UNSET))

        def _parse_remediation_effort(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation_effort = _parse_remediation_effort(d.pop("remediation_effort", UNSET))

        false_positive = d.pop("false_positive", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: NormalizedFindingMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = NormalizedFindingMetadata.from_dict(_metadata)

        normalized_finding = cls(
            finding_id=finding_id,
            title=title,
            severity=severity,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            component=component,
            version=version,
            file_path=file_path,
            line_number=line_number,
            remediation=remediation,
            remediation_effort=remediation_effort,
            false_positive=false_positive,
            tags=tags,
            metadata=metadata,
        )

        normalized_finding.additional_properties = d
        return normalized_finding

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
