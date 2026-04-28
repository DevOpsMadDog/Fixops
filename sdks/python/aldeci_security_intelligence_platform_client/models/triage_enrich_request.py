from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.triage_finding_input import TriageFindingInput


T = TypeVar("T", bound="TriageEnrichRequest")


@_attrs_define
class TriageEnrichRequest:
    """Request body for /enrich — single finding or batch.

    Attributes:
        findings (list[TriageFindingInput]): One or more findings to enrich
    """

    findings: list[TriageFindingInput]
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
        from ..models.triage_finding_input import TriageFindingInput

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = TriageFindingInput.from_dict(findings_item_data)

            findings.append(findings_item)

        triage_enrich_request = cls(
            findings=findings,
        )

        triage_enrich_request.additional_properties = d
        return triage_enrich_request

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
