from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddReportRequest")


@_attrs_define
class AddReportRequest:
    """
    Attributes:
        regulator (str):
        report_date (str):
        status (str | Unset):  Default: 'draft'.
        org_id (str | Unset):  Default: 'default'.
    """

    regulator: str
    report_date: str
    status: str | Unset = "draft"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        regulator = self.regulator

        report_date = self.report_date

        status = self.status

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "regulator": regulator,
                "report_date": report_date,
            }
        )
        if status is not UNSET:
            field_dict["status"] = status
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        regulator = d.pop("regulator")

        report_date = d.pop("report_date")

        status = d.pop("status", UNSET)

        org_id = d.pop("org_id", UNSET)

        add_report_request = cls(
            regulator=regulator,
            report_date=report_date,
            status=status,
            org_id=org_id,
        )

        add_report_request.additional_properties = d
        return add_report_request

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
