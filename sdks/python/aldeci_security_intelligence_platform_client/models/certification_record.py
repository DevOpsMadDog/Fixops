from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.compliance_cert import ComplianceCert
from ..types import UNSET, Unset

T = TypeVar("T", bound="CertificationRecord")


@_attrs_define
class CertificationRecord:
    """A compliance certification with validity dates.

    Attributes:
        cert (ComplianceCert):
        issued_date (str): ISO-8601 date certification issued
        expiry_date (str): ISO-8601 date certification expires
        issuing_body (None | str | Unset): Auditor or certification body
        report_url (None | str | Unset): Link to certification report
    """

    cert: ComplianceCert
    issued_date: str
    expiry_date: str
    issuing_body: None | str | Unset = UNSET
    report_url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cert = self.cert.value

        issued_date = self.issued_date

        expiry_date = self.expiry_date

        issuing_body: None | str | Unset
        if isinstance(self.issuing_body, Unset):
            issuing_body = UNSET
        else:
            issuing_body = self.issuing_body

        report_url: None | str | Unset
        if isinstance(self.report_url, Unset):
            report_url = UNSET
        else:
            report_url = self.report_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cert": cert,
                "issued_date": issued_date,
                "expiry_date": expiry_date,
            }
        )
        if issuing_body is not UNSET:
            field_dict["issuing_body"] = issuing_body
        if report_url is not UNSET:
            field_dict["report_url"] = report_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cert = ComplianceCert(d.pop("cert"))

        issued_date = d.pop("issued_date")

        expiry_date = d.pop("expiry_date")

        def _parse_issuing_body(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        issuing_body = _parse_issuing_body(d.pop("issuing_body", UNSET))

        def _parse_report_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        report_url = _parse_report_url(d.pop("report_url", UNSET))

        certification_record = cls(
            cert=cert,
            issued_date=issued_date,
            expiry_date=expiry_date,
            issuing_body=issuing_body,
            report_url=report_url,
        )

        certification_record.additional_properties = d
        return certification_record

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
