from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.findings_response_findings_item import FindingsResponseFindingsItem


T = TypeVar("T", bound="FindingsResponse")


@_attrs_define
class FindingsResponse:
    """
    Attributes:
        total (int):
        findings (list[FindingsResponseFindingsItem]):
    """

    total: int
    findings: list[FindingsResponseFindingsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total = self.total

        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total": total,
                "findings": findings,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.findings_response_findings_item import FindingsResponseFindingsItem

        d = dict(src_dict)
        total = d.pop("total")

        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = FindingsResponseFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        findings_response = cls(
            total=total,
            findings=findings,
        )

        findings_response.additional_properties = d
        return findings_response

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
