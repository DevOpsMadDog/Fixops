from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConsentCreate")


@_attrs_define
class ConsentCreate:
    """
    Attributes:
        subject_email (str):
        purpose (str | Unset):  Default: 'functional'.
        consent_given (bool | Unset):  Default: True.
        consent_date (None | str | Unset):
        source (str | Unset):  Default: 'website'.
        version (str | Unset):  Default: ''.
        ip_address (str | Unset):  Default: ''.
    """

    subject_email: str
    purpose: str | Unset = "functional"
    consent_given: bool | Unset = True
    consent_date: None | str | Unset = UNSET
    source: str | Unset = "website"
    version: str | Unset = ""
    ip_address: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subject_email = self.subject_email

        purpose = self.purpose

        consent_given = self.consent_given

        consent_date: None | str | Unset
        if isinstance(self.consent_date, Unset):
            consent_date = UNSET
        else:
            consent_date = self.consent_date

        source = self.source

        version = self.version

        ip_address = self.ip_address

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subject_email": subject_email,
            }
        )
        if purpose is not UNSET:
            field_dict["purpose"] = purpose
        if consent_given is not UNSET:
            field_dict["consent_given"] = consent_given
        if consent_date is not UNSET:
            field_dict["consent_date"] = consent_date
        if source is not UNSET:
            field_dict["source"] = source
        if version is not UNSET:
            field_dict["version"] = version
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        subject_email = d.pop("subject_email")

        purpose = d.pop("purpose", UNSET)

        consent_given = d.pop("consent_given", UNSET)

        def _parse_consent_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        consent_date = _parse_consent_date(d.pop("consent_date", UNSET))

        source = d.pop("source", UNSET)

        version = d.pop("version", UNSET)

        ip_address = d.pop("ip_address", UNSET)

        consent_create = cls(
            subject_email=subject_email,
            purpose=purpose,
            consent_given=consent_given,
            consent_date=consent_date,
            source=source,
            version=version,
            ip_address=ip_address,
        )

        consent_create.additional_properties = d
        return consent_create

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
