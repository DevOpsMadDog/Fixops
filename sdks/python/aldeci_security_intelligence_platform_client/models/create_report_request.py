from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateReportRequest")


@_attrs_define
class CreateReportRequest:
    """
    Attributes:
        report_name (str): Report name
        period_start (str): Period start ISO date
        period_end (str): Period end ISO date
        org_id (str | Unset): Organisation ID Default: 'default'.
        report_type (str | Unset): executive/board/audit/compliance/operational/monthly/quarterly/annual Default:
            'monthly'.
        audience (str | Unset): ciso/board/executives/auditors/regulators/team Default: 'ciso'.
        generated_by (str | Unset): Author or system that generated the report Default: ''.
    """

    report_name: str
    period_start: str
    period_end: str
    org_id: str | Unset = "default"
    report_type: str | Unset = "monthly"
    audience: str | Unset = "ciso"
    generated_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        report_name = self.report_name

        period_start = self.period_start

        period_end = self.period_end

        org_id = self.org_id

        report_type = self.report_type

        audience = self.audience

        generated_by = self.generated_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "report_name": report_name,
                "period_start": period_start,
                "period_end": period_end,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if report_type is not UNSET:
            field_dict["report_type"] = report_type
        if audience is not UNSET:
            field_dict["audience"] = audience
        if generated_by is not UNSET:
            field_dict["generated_by"] = generated_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        report_name = d.pop("report_name")

        period_start = d.pop("period_start")

        period_end = d.pop("period_end")

        org_id = d.pop("org_id", UNSET)

        report_type = d.pop("report_type", UNSET)

        audience = d.pop("audience", UNSET)

        generated_by = d.pop("generated_by", UNSET)

        create_report_request = cls(
            report_name=report_name,
            period_start=period_start,
            period_end=period_end,
            org_id=org_id,
            report_type=report_type,
            audience=audience,
            generated_by=generated_by,
        )

        create_report_request.additional_properties = d
        return create_report_request

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
