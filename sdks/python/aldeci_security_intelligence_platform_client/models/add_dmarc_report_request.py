from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddDmarcReportRequest")


@_attrs_define
class AddDmarcReportRequest:
    """
    Attributes:
        domain_id (str): Domain ID the report covers
        org_id (str | Unset): Organisation ID Default: 'default'.
        date (None | str | Unset): Report date (YYYY-MM-DD)
        pass_count (int | Unset): Messages that passed DMARC Default: 0.
        fail_count (int | Unset): Messages that failed DMARC Default: 0.
        quarantine_count (int | Unset): Messages quarantined Default: 0.
        reject_count (int | Unset): Messages rejected Default: 0.
        source_ips (list[str] | Unset): Observed source IPs
    """

    domain_id: str
    org_id: str | Unset = "default"
    date: None | str | Unset = UNSET
    pass_count: int | Unset = 0
    fail_count: int | Unset = 0
    quarantine_count: int | Unset = 0
    reject_count: int | Unset = 0
    source_ips: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain_id = self.domain_id

        org_id = self.org_id

        date: None | str | Unset
        if isinstance(self.date, Unset):
            date = UNSET
        else:
            date = self.date

        pass_count = self.pass_count

        fail_count = self.fail_count

        quarantine_count = self.quarantine_count

        reject_count = self.reject_count

        source_ips: list[str] | Unset = UNSET
        if not isinstance(self.source_ips, Unset):
            source_ips = self.source_ips

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain_id": domain_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if date is not UNSET:
            field_dict["date"] = date
        if pass_count is not UNSET:
            field_dict["pass_count"] = pass_count
        if fail_count is not UNSET:
            field_dict["fail_count"] = fail_count
        if quarantine_count is not UNSET:
            field_dict["quarantine_count"] = quarantine_count
        if reject_count is not UNSET:
            field_dict["reject_count"] = reject_count
        if source_ips is not UNSET:
            field_dict["source_ips"] = source_ips

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain_id = d.pop("domain_id")

        org_id = d.pop("org_id", UNSET)

        def _parse_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date = _parse_date(d.pop("date", UNSET))

        pass_count = d.pop("pass_count", UNSET)

        fail_count = d.pop("fail_count", UNSET)

        quarantine_count = d.pop("quarantine_count", UNSET)

        reject_count = d.pop("reject_count", UNSET)

        source_ips = cast(list[str], d.pop("source_ips", UNSET))

        add_dmarc_report_request = cls(
            domain_id=domain_id,
            org_id=org_id,
            date=date,
            pass_count=pass_count,
            fail_count=fail_count,
            quarantine_count=quarantine_count,
            reject_count=reject_count,
            source_ips=source_ips,
        )

        add_dmarc_report_request.additional_properties = d
        return add_dmarc_report_request

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
