from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterCertRequest")


@_attrs_define
class RegisterCertRequest:
    """
    Attributes:
        asset_id (str): Asset this certificate belongs to
        asset_name (str):
        subject (str):
        issuer (str):
        valid_from (str):
        valid_to (str):
        days_until_expiry (int):
        org_id (str | Unset):  Default: 'default'.
        san_domains (list[str] | Unset):
        is_expired (bool | Unset):  Default: False.
        is_self_signed (bool | Unset):  Default: False.
        tls_version (str | Unset):  Default: 'TLS 1.2'.
        cipher_suite (str | Unset):  Default: ''.
        grade (str | Unset):  Default: 'A'.
    """

    asset_id: str
    asset_name: str
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    days_until_expiry: int
    org_id: str | Unset = "default"
    san_domains: list[str] | Unset = UNSET
    is_expired: bool | Unset = False
    is_self_signed: bool | Unset = False
    tls_version: str | Unset = "TLS 1.2"
    cipher_suite: str | Unset = ""
    grade: str | Unset = "A"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        asset_name = self.asset_name

        subject = self.subject

        issuer = self.issuer

        valid_from = self.valid_from

        valid_to = self.valid_to

        days_until_expiry = self.days_until_expiry

        org_id = self.org_id

        san_domains: list[str] | Unset = UNSET
        if not isinstance(self.san_domains, Unset):
            san_domains = self.san_domains

        is_expired = self.is_expired

        is_self_signed = self.is_self_signed

        tls_version = self.tls_version

        cipher_suite = self.cipher_suite

        grade = self.grade

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
                "asset_name": asset_name,
                "subject": subject,
                "issuer": issuer,
                "valid_from": valid_from,
                "valid_to": valid_to,
                "days_until_expiry": days_until_expiry,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if san_domains is not UNSET:
            field_dict["san_domains"] = san_domains
        if is_expired is not UNSET:
            field_dict["is_expired"] = is_expired
        if is_self_signed is not UNSET:
            field_dict["is_self_signed"] = is_self_signed
        if tls_version is not UNSET:
            field_dict["tls_version"] = tls_version
        if cipher_suite is not UNSET:
            field_dict["cipher_suite"] = cipher_suite
        if grade is not UNSET:
            field_dict["grade"] = grade

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        asset_name = d.pop("asset_name")

        subject = d.pop("subject")

        issuer = d.pop("issuer")

        valid_from = d.pop("valid_from")

        valid_to = d.pop("valid_to")

        days_until_expiry = d.pop("days_until_expiry")

        org_id = d.pop("org_id", UNSET)

        san_domains = cast(list[str], d.pop("san_domains", UNSET))

        is_expired = d.pop("is_expired", UNSET)

        is_self_signed = d.pop("is_self_signed", UNSET)

        tls_version = d.pop("tls_version", UNSET)

        cipher_suite = d.pop("cipher_suite", UNSET)

        grade = d.pop("grade", UNSET)

        register_cert_request = cls(
            asset_id=asset_id,
            asset_name=asset_name,
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_to=valid_to,
            days_until_expiry=days_until_expiry,
            org_id=org_id,
            san_domains=san_domains,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            grade=grade,
        )

        register_cert_request.additional_properties = d
        return register_cert_request

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
