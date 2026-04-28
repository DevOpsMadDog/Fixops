from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.batch_enrich_request_findings_item import BatchEnrichRequestFindingsItem


T = TypeVar("T", bound="BatchEnrichRequest")


@_attrs_define
class BatchEnrichRequest:
    """Request body for batch enrichment.

    Attributes:
        findings (list[BatchEnrichRequestFindingsItem]): List of raw scanner findings (max 500)
    """

    findings: list[BatchEnrichRequestFindingsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.batch_enrich_request_findings_item import BatchEnrichRequestFindingsItem

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = BatchEnrichRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        batch_enrich_request = cls(
            findings=findings,
        )

        batch_enrich_request.additional_properties = d
        return batch_enrich_request

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
