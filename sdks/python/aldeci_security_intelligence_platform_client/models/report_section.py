from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.report_section_data import ReportSectionData


T = TypeVar("T", bound="ReportSection")


@_attrs_define
class ReportSection:
    """A single section within an executive report.

    Attributes:
        title (str): Section heading
        description (str | Unset): Narrative description of this section Default: ''.
        data (ReportSectionData | Unset): Section data payload
        chart_type (None | str | Unset): Suggested visualization: bar, line, pie, table
        order (int | Unset): Display order within the report (ascending) Default: 0.
    """

    title: str
    description: str | Unset = ""
    data: ReportSectionData | Unset = UNSET
    chart_type: None | str | Unset = UNSET
    order: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.data, Unset):
            data = self.data.to_dict()

        chart_type: None | str | Unset
        if isinstance(self.chart_type, Unset):
            chart_type = UNSET
        else:
            chart_type = self.chart_type

        order = self.order

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if data is not UNSET:
            field_dict["data"] = data
        if chart_type is not UNSET:
            field_dict["chart_type"] = chart_type
        if order is not UNSET:
            field_dict["order"] = order

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.report_section_data import ReportSectionData

        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description", UNSET)

        _data = d.pop("data", UNSET)
        data: ReportSectionData | Unset
        if isinstance(_data, Unset):
            data = UNSET
        else:
            data = ReportSectionData.from_dict(_data)

        def _parse_chart_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        chart_type = _parse_chart_type(d.pop("chart_type", UNSET))

        order = d.pop("order", UNSET)

        report_section = cls(
            title=title,
            description=description,
            data=data,
            chart_type=chart_type,
            order=order,
        )

        report_section.additional_properties = d
        return report_section

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
