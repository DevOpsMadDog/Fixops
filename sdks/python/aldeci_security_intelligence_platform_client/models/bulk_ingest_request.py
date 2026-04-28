from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.bulk_ingest_request_findings_item import BulkIngestRequestFindingsItem


T = TypeVar("T", bound="BulkIngestRequest")


@_attrs_define
class BulkIngestRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        findings (list[BulkIngestRequestFindingsItem]): List of finding dicts
    """

    org_id: str
    findings: list[BulkIngestRequestFindingsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "findings": findings,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bulk_ingest_request_findings_item import BulkIngestRequestFindingsItem

        d = dict(src_dict)
        org_id = d.pop("org_id")

        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = BulkIngestRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        bulk_ingest_request = cls(
            org_id=org_id,
            findings=findings,
        )

        bulk_ingest_request.additional_properties = d
        return bulk_ingest_request

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
