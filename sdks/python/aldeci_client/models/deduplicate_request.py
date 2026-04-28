from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.deduplicate_request_findings_item import DeduplicateRequestFindingsItem


T = TypeVar("T", bound="DeduplicateRequest")


@_attrs_define
class DeduplicateRequest:
    """
    Attributes:
        findings (list[DeduplicateRequestFindingsItem]): List of finding dicts to deduplicate
        org_id (str | Unset): Tenant / org identifier Default: ''.
        fuzzy_threshold (float | Unset): Levenshtein ratio threshold for fuzzy title matching (0-1) Default: 0.82.
    """

    findings: list[DeduplicateRequestFindingsItem]
    org_id: str | Unset = ""
    fuzzy_threshold: float | Unset = 0.82
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        org_id = self.org_id

        fuzzy_threshold = self.fuzzy_threshold

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if fuzzy_threshold is not UNSET:
            field_dict["fuzzy_threshold"] = fuzzy_threshold

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.deduplicate_request_findings_item import DeduplicateRequestFindingsItem

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = DeduplicateRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        org_id = d.pop("org_id", UNSET)

        fuzzy_threshold = d.pop("fuzzy_threshold", UNSET)

        deduplicate_request = cls(
            findings=findings,
            org_id=org_id,
            fuzzy_threshold=fuzzy_threshold,
        )

        deduplicate_request.additional_properties = d
        return deduplicate_request

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
