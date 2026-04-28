from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddCertRequest")


@_attrs_define
class AddCertRequest:
    """
    Attributes:
        domain (str): Primary domain
        org_id (str | Unset): Organisation ID Default: 'default'.
        issuer (str | Unset): Certificate issuer CN/O Default: ''.
        serial (str | Unset): Serial number Default: ''.
        not_before (str | Unset): Validity start (ISO-8601) Default: ''.
        not_after (str | Unset): Validity end (ISO-8601) Default: ''.
        algorithm (str | Unset): Signature algorithm (e.g. sha256WithRSAEncryption) Default: ''.
        key_size (int | Unset): Public key size in bits Default: 0.
        san_list (list[str] | Unset): Subject Alternative Names
        wildcard (bool | Unset): Wildcard certificate flag Default: False.
    """

    domain: str
    org_id: str | Unset = "default"
    issuer: str | Unset = ""
    serial: str | Unset = ""
    not_before: str | Unset = ""
    not_after: str | Unset = ""
    algorithm: str | Unset = ""
    key_size: int | Unset = 0
    san_list: list[str] | Unset = UNSET
    wildcard: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        org_id = self.org_id

        issuer = self.issuer

        serial = self.serial

        not_before = self.not_before

        not_after = self.not_after

        algorithm = self.algorithm

        key_size = self.key_size

        san_list: list[str] | Unset = UNSET
        if not isinstance(self.san_list, Unset):
            san_list = self.san_list

        wildcard = self.wildcard

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain": domain,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if issuer is not UNSET:
            field_dict["issuer"] = issuer
        if serial is not UNSET:
            field_dict["serial"] = serial
        if not_before is not UNSET:
            field_dict["not_before"] = not_before
        if not_after is not UNSET:
            field_dict["not_after"] = not_after
        if algorithm is not UNSET:
            field_dict["algorithm"] = algorithm
        if key_size is not UNSET:
            field_dict["key_size"] = key_size
        if san_list is not UNSET:
            field_dict["san_list"] = san_list
        if wildcard is not UNSET:
            field_dict["wildcard"] = wildcard

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        org_id = d.pop("org_id", UNSET)

        issuer = d.pop("issuer", UNSET)

        serial = d.pop("serial", UNSET)

        not_before = d.pop("not_before", UNSET)

        not_after = d.pop("not_after", UNSET)

        algorithm = d.pop("algorithm", UNSET)

        key_size = d.pop("key_size", UNSET)

        san_list = cast(list[str], d.pop("san_list", UNSET))

        wildcard = d.pop("wildcard", UNSET)

        add_cert_request = cls(
            domain=domain,
            org_id=org_id,
            issuer=issuer,
            serial=serial,
            not_before=not_before,
            not_after=not_after,
            algorithm=algorithm,
            key_size=key_size,
            san_list=san_list,
            wildcard=wildcard,
        )

        add_cert_request.additional_properties = d
        return add_cert_request

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
