from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.assess_framework_request_findings_item import AssessFrameworkRequestFindingsItem


T = TypeVar("T", bound="AssessFrameworkRequest")


@_attrs_define
class AssessFrameworkRequest:
    """
    Attributes:
        framework (str): Framework to assess (soc2, pci_dss_4.0, etc.)
        findings (list[AssessFrameworkRequestFindingsItem] | Unset):
    """

    framework: str
    findings: list[AssessFrameworkRequestFindingsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        findings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.findings, Unset):
            findings = []
            for findings_item_data in self.findings:
                findings_item = findings_item_data.to_dict()
                findings.append(findings_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
            }
        )
        if findings is not UNSET:
            field_dict["findings"] = findings

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.assess_framework_request_findings_item import AssessFrameworkRequestFindingsItem

        d = dict(src_dict)
        framework = d.pop("framework")

        _findings = d.pop("findings", UNSET)
        findings: list[AssessFrameworkRequestFindingsItem] | Unset = UNSET
        if _findings is not UNSET:
            findings = []
            for findings_item_data in _findings:
                findings_item = AssessFrameworkRequestFindingsItem.from_dict(findings_item_data)

                findings.append(findings_item)

        assess_framework_request = cls(
            framework=framework,
            findings=findings,
        )

        assess_framework_request.additional_properties = d
        return assess_framework_request

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
