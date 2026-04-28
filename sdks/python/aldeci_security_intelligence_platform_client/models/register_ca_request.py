from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterCARequest")


@_attrs_define
class RegisterCARequest:
    """
    Attributes:
        name (str): CA name
        ca_type (str): root | intermediate | external
        subject (None | str | Unset): CA subject DN Default: ''.
        key_algorithm (None | str | Unset): Key algorithm Default: 'RSA'.
        status (None | str | Unset): active | inactive | compromised Default: 'active'.
        cert_count (int | None | Unset): Certificates issued Default: 0.
    """

    name: str
    ca_type: str
    subject: None | str | Unset = ""
    key_algorithm: None | str | Unset = "RSA"
    status: None | str | Unset = "active"
    cert_count: int | None | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        ca_type = self.ca_type

        subject: None | str | Unset
        if isinstance(self.subject, Unset):
            subject = UNSET
        else:
            subject = self.subject

        key_algorithm: None | str | Unset
        if isinstance(self.key_algorithm, Unset):
            key_algorithm = UNSET
        else:
            key_algorithm = self.key_algorithm

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        cert_count: int | None | Unset
        if isinstance(self.cert_count, Unset):
            cert_count = UNSET
        else:
            cert_count = self.cert_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "ca_type": ca_type,
            }
        )
        if subject is not UNSET:
            field_dict["subject"] = subject
        if key_algorithm is not UNSET:
            field_dict["key_algorithm"] = key_algorithm
        if status is not UNSET:
            field_dict["status"] = status
        if cert_count is not UNSET:
            field_dict["cert_count"] = cert_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        ca_type = d.pop("ca_type")

        def _parse_subject(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        subject = _parse_subject(d.pop("subject", UNSET))

        def _parse_key_algorithm(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        key_algorithm = _parse_key_algorithm(d.pop("key_algorithm", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_cert_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        cert_count = _parse_cert_count(d.pop("cert_count", UNSET))

        register_ca_request = cls(
            name=name,
            ca_type=ca_type,
            subject=subject,
            key_algorithm=key_algorithm,
            status=status,
            cert_count=cert_count,
        )

        register_ca_request.additional_properties = d
        return register_ca_request

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
