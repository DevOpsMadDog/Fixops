from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ComplianceBadge")


@_attrs_define
class ComplianceBadge:
    """A compliance certification or attestation badge.

    Attributes:
        framework (str):
        status (str):
        id (str | Unset):
        certified_date (None | str | Unset):
        auditor (None | str | Unset):
        report_url (None | str | Unset):
        org_id (str | Unset):  Default: ''.
    """

    framework: str
    status: str
    id: str | Unset = UNSET
    certified_date: None | str | Unset = UNSET
    auditor: None | str | Unset = UNSET
    report_url: None | str | Unset = UNSET
    org_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        status = self.status

        id = self.id

        certified_date: None | str | Unset
        if isinstance(self.certified_date, Unset):
            certified_date = UNSET
        else:
            certified_date = self.certified_date

        auditor: None | str | Unset
        if isinstance(self.auditor, Unset):
            auditor = UNSET
        else:
            auditor = self.auditor

        report_url: None | str | Unset
        if isinstance(self.report_url, Unset):
            report_url = UNSET
        else:
            report_url = self.report_url

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
                "status": status,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if certified_date is not UNSET:
            field_dict["certified_date"] = certified_date
        if auditor is not UNSET:
            field_dict["auditor"] = auditor
        if report_url is not UNSET:
            field_dict["report_url"] = report_url
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = d.pop("framework")

        status = d.pop("status")

        id = d.pop("id", UNSET)

        def _parse_certified_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        certified_date = _parse_certified_date(d.pop("certified_date", UNSET))

        def _parse_auditor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        auditor = _parse_auditor(d.pop("auditor", UNSET))

        def _parse_report_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        report_url = _parse_report_url(d.pop("report_url", UNSET))

        org_id = d.pop("org_id", UNSET)

        compliance_badge = cls(
            framework=framework,
            status=status,
            id=id,
            certified_date=certified_date,
            auditor=auditor,
            report_url=report_url,
            org_id=org_id,
        )

        compliance_badge.additional_properties = d
        return compliance_badge

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
