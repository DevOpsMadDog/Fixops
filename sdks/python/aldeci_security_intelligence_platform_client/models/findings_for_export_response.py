from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.finding_export_target import FindingExportTarget

if TYPE_CHECKING:
    from ..models.finding_for_export import FindingForExport


T = TypeVar("T", bound="FindingsForExportResponse")


@_attrs_define
class FindingsForExportResponse:
    """Response for GET /api/v1/findings/pending-export.

    Attributes:
        target (FindingExportTarget): External systems for finding export.
        findings (list[FindingForExport]): Findings ready to export
        total_count (int): Total pending for target
        since (datetime.datetime): Findings modified since this time
    """

    target: FindingExportTarget
    findings: list[FindingForExport]
    total_count: int
    since: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target = self.target.value

        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        total_count = self.total_count

        since = self.since.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target": target,
                "findings": findings,
                "total_count": total_count,
                "since": since,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_for_export import FindingForExport

        d = dict(src_dict)
        target = FindingExportTarget(d.pop("target"))

        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = FindingForExport.from_dict(findings_item_data)

            findings.append(findings_item)

        total_count = d.pop("total_count")

        since = isoparse(d.pop("since"))

        findings_for_export_response = cls(
            target=target,
            findings=findings,
            total_count=total_count,
            since=since,
        )

        findings_for_export_response.additional_properties = d
        return findings_for_export_response

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
