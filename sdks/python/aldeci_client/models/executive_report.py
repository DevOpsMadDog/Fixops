from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.report_frequency import ReportFrequency
from ..models.report_type import ReportType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.executive_report_metadata import ExecutiveReportMetadata
    from ..models.report_section import ReportSection


T = TypeVar("T", bound="ExecutiveReport")


@_attrs_define
class ExecutiveReport:
    """A complete executive report.

    Attributes:
        title (str):
        type_ (ReportType): Types of executive reports.
        period_start (str):
        period_end (str):
        id (str | Unset):
        frequency (ReportFrequency | Unset): Report generation frequency.
        org_id (str | Unset):  Default: 'default'.
        created_at (str | Unset):
        sections (list[ReportSection] | Unset):
        metadata (ExecutiveReportMetadata | Unset):
        generated_by (str | Unset):  Default: 'executive_report_engine'.
    """

    title: str
    type_: ReportType
    period_start: str
    period_end: str
    id: str | Unset = UNSET
    frequency: ReportFrequency | Unset = UNSET
    org_id: str | Unset = "default"
    created_at: str | Unset = UNSET
    sections: list[ReportSection] | Unset = UNSET
    metadata: ExecutiveReportMetadata | Unset = UNSET
    generated_by: str | Unset = "executive_report_engine"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        type_ = self.type_.value

        period_start = self.period_start

        period_end = self.period_end

        id = self.id

        frequency: str | Unset = UNSET
        if not isinstance(self.frequency, Unset):
            frequency = self.frequency.value

        org_id = self.org_id

        created_at = self.created_at

        sections: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.sections, Unset):
            sections = []
            for sections_item_data in self.sections:
                sections_item = sections_item_data.to_dict()
                sections.append(sections_item)

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        generated_by = self.generated_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "type": type_,
                "period_start": period_start,
                "period_end": period_end,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if frequency is not UNSET:
            field_dict["frequency"] = frequency
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if sections is not UNSET:
            field_dict["sections"] = sections
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if generated_by is not UNSET:
            field_dict["generated_by"] = generated_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.executive_report_metadata import ExecutiveReportMetadata
        from ..models.report_section import ReportSection

        d = dict(src_dict)
        title = d.pop("title")

        type_ = ReportType(d.pop("type"))

        period_start = d.pop("period_start")

        period_end = d.pop("period_end")

        id = d.pop("id", UNSET)

        _frequency = d.pop("frequency", UNSET)
        frequency: ReportFrequency | Unset
        if isinstance(_frequency, Unset):
            frequency = UNSET
        else:
            frequency = ReportFrequency(_frequency)

        org_id = d.pop("org_id", UNSET)

        created_at = d.pop("created_at", UNSET)

        _sections = d.pop("sections", UNSET)
        sections: list[ReportSection] | Unset = UNSET
        if _sections is not UNSET:
            sections = []
            for sections_item_data in _sections:
                sections_item = ReportSection.from_dict(sections_item_data)

                sections.append(sections_item)

        _metadata = d.pop("metadata", UNSET)
        metadata: ExecutiveReportMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = ExecutiveReportMetadata.from_dict(_metadata)

        generated_by = d.pop("generated_by", UNSET)

        executive_report = cls(
            title=title,
            type_=type_,
            period_start=period_start,
            period_end=period_end,
            id=id,
            frequency=frequency,
            org_id=org_id,
            created_at=created_at,
            sections=sections,
            metadata=metadata,
            generated_by=generated_by,
        )

        executive_report.additional_properties = d
        return executive_report

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
