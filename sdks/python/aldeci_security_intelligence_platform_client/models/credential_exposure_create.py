from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CredentialExposureCreate")


@_attrs_define
class CredentialExposureCreate:
    """
    Attributes:
        email_domain (str):
        source (str):
        exposure_count (int | Unset):  Default: 1.
        breach_date (None | str | Unset):
        verified (bool | Unset):  Default: False.
    """

    email_domain: str
    source: str
    exposure_count: int | Unset = 1
    breach_date: None | str | Unset = UNSET
    verified: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email_domain = self.email_domain

        source = self.source

        exposure_count = self.exposure_count

        breach_date: None | str | Unset
        if isinstance(self.breach_date, Unset):
            breach_date = UNSET
        else:
            breach_date = self.breach_date

        verified = self.verified

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "email_domain": email_domain,
                "source": source,
            }
        )
        if exposure_count is not UNSET:
            field_dict["exposure_count"] = exposure_count
        if breach_date is not UNSET:
            field_dict["breach_date"] = breach_date
        if verified is not UNSET:
            field_dict["verified"] = verified

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email_domain = d.pop("email_domain")

        source = d.pop("source")

        exposure_count = d.pop("exposure_count", UNSET)

        def _parse_breach_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        breach_date = _parse_breach_date(d.pop("breach_date", UNSET))

        verified = d.pop("verified", UNSET)

        credential_exposure_create = cls(
            email_domain=email_domain,
            source=source,
            exposure_count=exposure_count,
            breach_date=breach_date,
            verified=verified,
        )

        credential_exposure_create.additional_properties = d
        return credential_exposure_create

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
