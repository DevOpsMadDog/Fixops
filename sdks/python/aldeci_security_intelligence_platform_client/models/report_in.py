from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReportIn")


@_attrs_define
class ReportIn:
    """
    Attributes:
        report_type (str | Unset):  Default: 'monthly'.
        title (str | Unset):  Default: ''.
        period_start (str | Unset):  Default: ''.
        period_end (str | Unset):  Default: ''.
        sections (list[str] | Unset):
        created_by (str | Unset):  Default: ''.
    """

    report_type: str | Unset = "monthly"
    title: str | Unset = ""
    period_start: str | Unset = ""
    period_end: str | Unset = ""
    sections: list[str] | Unset = UNSET
    created_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        report_type = self.report_type

        title = self.title

        period_start = self.period_start

        period_end = self.period_end

        sections: list[str] | Unset = UNSET
        if not isinstance(self.sections, Unset):
            sections = self.sections

        created_by = self.created_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if report_type is not UNSET:
            field_dict["report_type"] = report_type
        if title is not UNSET:
            field_dict["title"] = title
        if period_start is not UNSET:
            field_dict["period_start"] = period_start
        if period_end is not UNSET:
            field_dict["period_end"] = period_end
        if sections is not UNSET:
            field_dict["sections"] = sections
        if created_by is not UNSET:
            field_dict["created_by"] = created_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        report_type = d.pop("report_type", UNSET)

        title = d.pop("title", UNSET)

        period_start = d.pop("period_start", UNSET)

        period_end = d.pop("period_end", UNSET)

        sections = cast(list[str], d.pop("sections", UNSET))

        created_by = d.pop("created_by", UNSET)

        report_in = cls(
            report_type=report_type,
            title=title,
            period_start=period_start,
            period_end=period_end,
            sections=sections,
            created_by=created_by,
        )

        report_in.additional_properties = d
        return report_in

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
