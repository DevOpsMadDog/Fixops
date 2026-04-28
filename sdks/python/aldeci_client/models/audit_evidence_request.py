from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.compliance_framework import ComplianceFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="AuditEvidenceRequest")


@_attrs_define
class AuditEvidenceRequest:
    """Request for audit evidence collection.

    Attributes:
        framework (ComplianceFramework): Compliance frameworks.
        controls (list[str] | Unset):
        format_ (str | Unset):  Default: 'pdf'.
    """

    framework: ComplianceFramework
    controls: list[str] | Unset = UNSET
    format_: str | Unset = "pdf"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework.value

        controls: list[str] | Unset = UNSET
        if not isinstance(self.controls, Unset):
            controls = self.controls

        format_ = self.format_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
            }
        )
        if controls is not UNSET:
            field_dict["controls"] = controls
        if format_ is not UNSET:
            field_dict["format"] = format_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = ComplianceFramework(d.pop("framework"))

        controls = cast(list[str], d.pop("controls", UNSET))

        format_ = d.pop("format", UNSET)

        audit_evidence_request = cls(
            framework=framework,
            controls=controls,
            format_=format_,
        )

        audit_evidence_request.additional_properties = d
        return audit_evidence_request

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
