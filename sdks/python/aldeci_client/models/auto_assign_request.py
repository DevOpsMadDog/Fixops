from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.auto_assign_request_findings_item import AutoAssignRequestFindingsItem


T = TypeVar("T", bound="AutoAssignRequest")


@_attrs_define
class AutoAssignRequest:
    """
    Attributes:
        findings (list[AutoAssignRequestFindingsItem]): List of finding dicts
        org_id (str | Unset):  Default: 'default'.
    """

    findings: list[AutoAssignRequestFindingsItem]
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auto_assign_request_findings_item import AutoAssignRequestFindingsItem

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = AutoAssignRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        org_id = d.pop("org_id", UNSET)

        auto_assign_request = cls(
            findings=findings,
            org_id=org_id,
        )

        auto_assign_request.additional_properties = d
        return auto_assign_request

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
