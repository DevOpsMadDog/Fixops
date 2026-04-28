from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="TLSCertificate")


@_attrs_define
class TLSCertificate:
    """
    Attributes:
        org_id (str):
        host (str):
        subject_cn (str):
        issuer (str):
        not_before (datetime.datetime):
        not_after (datetime.datetime):
        id (str | Unset):
        port (int | Unset):  Default: 443.
        protocol_version (str | Unset):  Default: 'TLSv1.3'.
        cipher_suite (str | Unset):  Default: ''.
        ct_logged (bool | Unset):  Default: True.
        san_domains (list[str] | Unset):
        observed_at (datetime.datetime | Unset):
    """

    org_id: str
    host: str
    subject_cn: str
    issuer: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    id: str | Unset = UNSET
    port: int | Unset = 443
    protocol_version: str | Unset = "TLSv1.3"
    cipher_suite: str | Unset = ""
    ct_logged: bool | Unset = True
    san_domains: list[str] | Unset = UNSET
    observed_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        host = self.host

        subject_cn = self.subject_cn

        issuer = self.issuer

        not_before = self.not_before.isoformat()

        not_after = self.not_after.isoformat()

        id = self.id

        port = self.port

        protocol_version = self.protocol_version

        cipher_suite = self.cipher_suite

        ct_logged = self.ct_logged

        san_domains: list[str] | Unset = UNSET
        if not isinstance(self.san_domains, Unset):
            san_domains = self.san_domains

        observed_at: str | Unset = UNSET
        if not isinstance(self.observed_at, Unset):
            observed_at = self.observed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "host": host,
                "subject_cn": subject_cn,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if port is not UNSET:
            field_dict["port"] = port
        if protocol_version is not UNSET:
            field_dict["protocol_version"] = protocol_version
        if cipher_suite is not UNSET:
            field_dict["cipher_suite"] = cipher_suite
        if ct_logged is not UNSET:
            field_dict["ct_logged"] = ct_logged
        if san_domains is not UNSET:
            field_dict["san_domains"] = san_domains
        if observed_at is not UNSET:
            field_dict["observed_at"] = observed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        host = d.pop("host")

        subject_cn = d.pop("subject_cn")

        issuer = d.pop("issuer")

        not_before = isoparse(d.pop("not_before"))

        not_after = isoparse(d.pop("not_after"))

        id = d.pop("id", UNSET)

        port = d.pop("port", UNSET)

        protocol_version = d.pop("protocol_version", UNSET)

        cipher_suite = d.pop("cipher_suite", UNSET)

        ct_logged = d.pop("ct_logged", UNSET)

        san_domains = cast(list[str], d.pop("san_domains", UNSET))

        _observed_at = d.pop("observed_at", UNSET)
        observed_at: datetime.datetime | Unset
        if isinstance(_observed_at, Unset):
            observed_at = UNSET
        else:
            observed_at = isoparse(_observed_at)

        tls_certificate = cls(
            org_id=org_id,
            host=host,
            subject_cn=subject_cn,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            id=id,
            port=port,
            protocol_version=protocol_version,
            cipher_suite=cipher_suite,
            ct_logged=ct_logged,
            san_domains=san_domains,
            observed_at=observed_at,
        )

        tls_certificate.additional_properties = d
        return tls_certificate

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
