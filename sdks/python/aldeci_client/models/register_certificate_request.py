from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterCertificateRequest")


@_attrs_define
class RegisterCertificateRequest:
    """
    Attributes:
        domain (str | Unset): Primary domain / subject CN Default: ''.
        issuer (str | Unset): Certificate Authority name Default: ''.
        cert_type (str | Unset): Certificate type: ssl | code_signing | client | ca Default: 'ssl'.
        expiry_date (str | Unset): Expiry timestamp in ISO 8601 format (e.g. 2027-01-01T00:00:00+00:00) Default: ''.
        san_list (list[str] | Unset): Subject Alternative Names
        auto_renew (bool | Unset): Whether to auto-renew before expiry Default: False.
    """

    domain: str | Unset = ""
    issuer: str | Unset = ""
    cert_type: str | Unset = "ssl"
    expiry_date: str | Unset = ""
    san_list: list[str] | Unset = UNSET
    auto_renew: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        issuer = self.issuer

        cert_type = self.cert_type

        expiry_date = self.expiry_date

        san_list: list[str] | Unset = UNSET
        if not isinstance(self.san_list, Unset):
            san_list = self.san_list

        auto_renew = self.auto_renew

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if domain is not UNSET:
            field_dict["domain"] = domain
        if issuer is not UNSET:
            field_dict["issuer"] = issuer
        if cert_type is not UNSET:
            field_dict["cert_type"] = cert_type
        if expiry_date is not UNSET:
            field_dict["expiry_date"] = expiry_date
        if san_list is not UNSET:
            field_dict["san_list"] = san_list
        if auto_renew is not UNSET:
            field_dict["auto_renew"] = auto_renew

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain", UNSET)

        issuer = d.pop("issuer", UNSET)

        cert_type = d.pop("cert_type", UNSET)

        expiry_date = d.pop("expiry_date", UNSET)

        san_list = cast(list[str], d.pop("san_list", UNSET))

        auto_renew = d.pop("auto_renew", UNSET)

        register_certificate_request = cls(
            domain=domain,
            issuer=issuer,
            cert_type=cert_type,
            expiry_date=expiry_date,
            san_list=san_list,
            auto_renew=auto_renew,
        )

        register_certificate_request.additional_properties = d
        return register_certificate_request

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
