from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.report_frequency import ReportFrequency
from ..models.report_type import ReportType
from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateScheduleRequest")


@_attrs_define
class CreateScheduleRequest:
    """Request body for schedule creation.

    Attributes:
        report_type (ReportType): Types of executive reports.
        frequency (ReportFrequency): Report generation frequency.
        recipients (list[str] | Unset): Email addresses or identifiers for delivery
        org_id (str | Unset): Organisation identifier Default: 'default'.
    """

    report_type: ReportType
    frequency: ReportFrequency
    recipients: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        report_type = self.report_type.value

        frequency = self.frequency.value

        recipients: list[str] | Unset = UNSET
        if not isinstance(self.recipients, Unset):
            recipients = self.recipients

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "report_type": report_type,
                "frequency": frequency,
            }
        )
        if recipients is not UNSET:
            field_dict["recipients"] = recipients
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        report_type = ReportType(d.pop("report_type"))

        frequency = ReportFrequency(d.pop("frequency"))

        recipients = cast(list[str], d.pop("recipients", UNSET))

        org_id = d.pop("org_id", UNSET)

        create_schedule_request = cls(
            report_type=report_type,
            frequency=frequency,
            recipients=recipients,
            org_id=org_id,
        )

        create_schedule_request.additional_properties = d
        return create_schedule_request

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
