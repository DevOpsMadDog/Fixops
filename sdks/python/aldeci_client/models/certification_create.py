from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CertificationCreate")


@_attrs_define
class CertificationCreate:
    """
    Attributes:
        cert_name (str):
        cert_provider (str | Unset):  Default: ''.
        issued_at (None | str | Unset):
        expires_at (None | str | Unset):
        status (str | Unset):  Default: 'valid'.
    """

    cert_name: str
    cert_provider: str | Unset = ""
    issued_at: None | str | Unset = UNSET
    expires_at: None | str | Unset = UNSET
    status: str | Unset = "valid"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cert_name = self.cert_name

        cert_provider = self.cert_provider

        issued_at: None | str | Unset
        if isinstance(self.issued_at, Unset):
            issued_at = UNSET
        else:
            issued_at = self.issued_at

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cert_name": cert_name,
            }
        )
        if cert_provider is not UNSET:
            field_dict["cert_provider"] = cert_provider
        if issued_at is not UNSET:
            field_dict["issued_at"] = issued_at
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cert_name = d.pop("cert_name")

        cert_provider = d.pop("cert_provider", UNSET)

        def _parse_issued_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        issued_at = _parse_issued_at(d.pop("issued_at", UNSET))

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        status = d.pop("status", UNSET)

        certification_create = cls(
            cert_name=cert_name,
            cert_provider=cert_provider,
            issued_at=issued_at,
            expires_at=expires_at,
            status=status,
        )

        certification_create.additional_properties = d
        return certification_create

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
