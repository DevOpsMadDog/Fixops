from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.finding_request_extra import FindingRequestExtra


T = TypeVar("T", bound="FindingRequest")


@_attrs_define
class FindingRequest:
    """A finding to create or sync as a GitHub issue.

    Attributes:
        finding_id (str): Unique finding identifier
        title (str): Short finding title
        severity (str): critical | high | medium | low | informational
        finding_type (str | Unset): sast | dast | sca | iac | secret | cloud | network Default: 'sast'.
        description (str | Unset): Full finding description (Markdown) Default: ''.
        cwe (None | str | Unset): CWE identifier, e.g. 'CWE-79'
        cvss (float | None | Unset): CVSS score, e.g. 9.8
        affected_file (None | str | Unset): Source file path
        affected_line (int | None | Unset): Line number in affected file
        remediation (None | str | Unset): Remediation guidance (Markdown)
        scanner (None | str | Unset): Scanner that found this (semgrep, trivy, etc.)
        cve_id (None | str | Unset): CVE identifier, e.g. 'CVE-2024-1234'
        status (str | Unset): open | resolved | in_progress | accepted_risk Default: 'open'.
        extra (FindingRequestExtra | Unset): Additional metadata
    """

    finding_id: str
    title: str
    severity: str
    finding_type: str | Unset = "sast"
    description: str | Unset = ""
    cwe: None | str | Unset = UNSET
    cvss: float | None | Unset = UNSET
    affected_file: None | str | Unset = UNSET
    affected_line: int | None | Unset = UNSET
    remediation: None | str | Unset = UNSET
    scanner: None | str | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    status: str | Unset = "open"
    extra: FindingRequestExtra | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        title = self.title

        severity = self.severity

        finding_type = self.finding_type

        description = self.description

        cwe: None | str | Unset
        if isinstance(self.cwe, Unset):
            cwe = UNSET
        else:
            cwe = self.cwe

        cvss: float | None | Unset
        if isinstance(self.cvss, Unset):
            cvss = UNSET
        else:
            cvss = self.cvss

        affected_file: None | str | Unset
        if isinstance(self.affected_file, Unset):
            affected_file = UNSET
        else:
            affected_file = self.affected_file

        affected_line: int | None | Unset
        if isinstance(self.affected_line, Unset):
            affected_line = UNSET
        else:
            affected_line = self.affected_line

        remediation: None | str | Unset
        if isinstance(self.remediation, Unset):
            remediation = UNSET
        else:
            remediation = self.remediation

        scanner: None | str | Unset
        if isinstance(self.scanner, Unset):
            scanner = UNSET
        else:
            scanner = self.scanner

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        status = self.status

        extra: dict[str, Any] | Unset = UNSET
        if not isinstance(self.extra, Unset):
            extra = self.extra.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "title": title,
                "severity": severity,
            }
        )
        if finding_type is not UNSET:
            field_dict["finding_type"] = finding_type
        if description is not UNSET:
            field_dict["description"] = description
        if cwe is not UNSET:
            field_dict["cwe"] = cwe
        if cvss is not UNSET:
            field_dict["cvss"] = cvss
        if affected_file is not UNSET:
            field_dict["affected_file"] = affected_file
        if affected_line is not UNSET:
            field_dict["affected_line"] = affected_line
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if scanner is not UNSET:
            field_dict["scanner"] = scanner
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if status is not UNSET:
            field_dict["status"] = status
        if extra is not UNSET:
            field_dict["extra"] = extra

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_request_extra import FindingRequestExtra

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        title = d.pop("title")

        severity = d.pop("severity")

        finding_type = d.pop("finding_type", UNSET)

        description = d.pop("description", UNSET)

        def _parse_cwe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cwe = _parse_cwe(d.pop("cwe", UNSET))

        def _parse_cvss(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss = _parse_cvss(d.pop("cvss", UNSET))

        def _parse_affected_file(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        affected_file = _parse_affected_file(d.pop("affected_file", UNSET))

        def _parse_affected_line(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        affected_line = _parse_affected_line(d.pop("affected_line", UNSET))

        def _parse_remediation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation = _parse_remediation(d.pop("remediation", UNSET))

        def _parse_scanner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scanner = _parse_scanner(d.pop("scanner", UNSET))

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        status = d.pop("status", UNSET)

        _extra = d.pop("extra", UNSET)
        extra: FindingRequestExtra | Unset
        if isinstance(_extra, Unset):
            extra = UNSET
        else:
            extra = FindingRequestExtra.from_dict(_extra)

        finding_request = cls(
            finding_id=finding_id,
            title=title,
            severity=severity,
            finding_type=finding_type,
            description=description,
            cwe=cwe,
            cvss=cvss,
            affected_file=affected_file,
            affected_line=affected_line,
            remediation=remediation,
            scanner=scanner,
            cve_id=cve_id,
            status=status,
            extra=extra,
        )

        finding_request.additional_properties = d
        return finding_request

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
