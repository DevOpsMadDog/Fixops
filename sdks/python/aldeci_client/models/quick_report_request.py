from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="QuickReportRequest")


@_attrs_define
class QuickReportRequest:
    """Quick report generation request.

    Attributes:
        report_type (str | Unset): Report type Default: 'executive'.
        finding_ids (list[str] | Unset):
        include_remediation (bool | Unset):  Default: True.
        format_ (str | Unset): Output format Default: 'pdf'.
    """

    report_type: str | Unset = "executive"
    finding_ids: list[str] | Unset = UNSET
    include_remediation: bool | Unset = True
    format_: str | Unset = "pdf"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        report_type = self.report_type

        finding_ids: list[str] | Unset = UNSET
        if not isinstance(self.finding_ids, Unset):
            finding_ids = self.finding_ids

        include_remediation = self.include_remediation

        format_ = self.format_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if report_type is not UNSET:
            field_dict["report_type"] = report_type
        if finding_ids is not UNSET:
            field_dict["finding_ids"] = finding_ids
        if include_remediation is not UNSET:
            field_dict["include_remediation"] = include_remediation
        if format_ is not UNSET:
            field_dict["format"] = format_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        report_type = d.pop("report_type", UNSET)

        finding_ids = cast(list[str], d.pop("finding_ids", UNSET))

        include_remediation = d.pop("include_remediation", UNSET)

        format_ = d.pop("format", UNSET)

        quick_report_request = cls(
            report_type=report_type,
            finding_ids=finding_ids,
            include_remediation=include_remediation,
            format_=format_,
        )

        quick_report_request.additional_properties = d
        return quick_report_request

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
