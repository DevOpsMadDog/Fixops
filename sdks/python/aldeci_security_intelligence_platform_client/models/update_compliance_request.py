from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateComplianceRequest")


@_attrs_define
class UpdateComplianceRequest:
    """
    Attributes:
        compliance_score (int): Compliance score 0-100
        org_id (str | Unset): Organisation identifier Default: 'default'.
        issues (list[str] | Unset): List of compliance issues
    """

    compliance_score: int
    org_id: str | Unset = "default"
    issues: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        compliance_score = self.compliance_score

        org_id = self.org_id

        issues: list[str] | Unset = UNSET
        if not isinstance(self.issues, Unset):
            issues = self.issues

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "compliance_score": compliance_score,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if issues is not UNSET:
            field_dict["issues"] = issues

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        compliance_score = d.pop("compliance_score")

        org_id = d.pop("org_id", UNSET)

        issues = cast(list[str], d.pop("issues", UNSET))

        update_compliance_request = cls(
            compliance_score=compliance_score,
            org_id=org_id,
            issues=issues,
        )

        update_compliance_request.additional_properties = d
        return update_compliance_request

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
