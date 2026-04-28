from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.report_frequency import ReportFrequency
from ..models.report_type import ReportType
from ..types import UNSET, Unset

T = TypeVar("T", bound="ReportSchedule")


@_attrs_define
class ReportSchedule:
    """A scheduled report definition.

    Attributes:
        report_type (ReportType): Types of executive reports.
        frequency (ReportFrequency): Report generation frequency.
        next_run (str):
        id (str | Unset):
        recipients (list[str] | Unset):
        enabled (bool | Unset):  Default: True.
        org_id (str | Unset):  Default: 'default'.
    """

    report_type: ReportType
    frequency: ReportFrequency
    next_run: str
    id: str | Unset = UNSET
    recipients: list[str] | Unset = UNSET
    enabled: bool | Unset = True
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        report_type = self.report_type.value

        frequency = self.frequency.value

        next_run = self.next_run

        id = self.id

        recipients: list[str] | Unset = UNSET
        if not isinstance(self.recipients, Unset):
            recipients = self.recipients

        enabled = self.enabled

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "report_type": report_type,
                "frequency": frequency,
                "next_run": next_run,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if recipients is not UNSET:
            field_dict["recipients"] = recipients
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        report_type = ReportType(d.pop("report_type"))

        frequency = ReportFrequency(d.pop("frequency"))

        next_run = d.pop("next_run")

        id = d.pop("id", UNSET)

        recipients = cast(list[str], d.pop("recipients", UNSET))

        enabled = d.pop("enabled", UNSET)

        org_id = d.pop("org_id", UNSET)

        report_schedule = cls(
            report_type=report_type,
            frequency=frequency,
            next_run=next_run,
            id=id,
            recipients=recipients,
            enabled=enabled,
            org_id=org_id,
        )

        report_schedule.additional_properties = d
        return report_schedule

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
