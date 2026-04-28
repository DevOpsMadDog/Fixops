from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IssueCertificateRequest")


@_attrs_define
class IssueCertificateRequest:
    """
    Attributes:
        common_name (str): Common name (CN) for the certificate
        expires_at (str): ISO expiry timestamp
        serial_number (None | str | Unset): Serial number Default: ''.
        issuer (None | str | Unset): Issuing CA Default: ''.
        subject_alt_names (list[str] | None | Unset): SANs
        key_algorithm (None | str | Unset): RSA | ECDSA | DSA Default: 'RSA'.
        key_size (int | None | Unset): Key size in bits Default: 2048.
        cert_type (None | str | Unset): root_ca | intermediate_ca | server | client | code_signing | email Default:
            'server'.
        status (None | str | Unset): initial status Default: 'active'.
        issued_at (None | str | Unset): ISO issued timestamp
        auto_renew (bool | None | Unset): Auto-renew flag Default: False.
        actor (None | str | Unset): Issuing actor Default: 'system'.
    """

    common_name: str
    expires_at: str
    serial_number: None | str | Unset = ""
    issuer: None | str | Unset = ""
    subject_alt_names: list[str] | None | Unset = UNSET
    key_algorithm: None | str | Unset = "RSA"
    key_size: int | None | Unset = 2048
    cert_type: None | str | Unset = "server"
    status: None | str | Unset = "active"
    issued_at: None | str | Unset = UNSET
    auto_renew: bool | None | Unset = False
    actor: None | str | Unset = "system"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        common_name = self.common_name

        expires_at = self.expires_at

        serial_number: None | str | Unset
        if isinstance(self.serial_number, Unset):
            serial_number = UNSET
        else:
            serial_number = self.serial_number

        issuer: None | str | Unset
        if isinstance(self.issuer, Unset):
            issuer = UNSET
        else:
            issuer = self.issuer

        subject_alt_names: list[str] | None | Unset
        if isinstance(self.subject_alt_names, Unset):
            subject_alt_names = UNSET
        elif isinstance(self.subject_alt_names, list):
            subject_alt_names = self.subject_alt_names

        else:
            subject_alt_names = self.subject_alt_names

        key_algorithm: None | str | Unset
        if isinstance(self.key_algorithm, Unset):
            key_algorithm = UNSET
        else:
            key_algorithm = self.key_algorithm

        key_size: int | None | Unset
        if isinstance(self.key_size, Unset):
            key_size = UNSET
        else:
            key_size = self.key_size

        cert_type: None | str | Unset
        if isinstance(self.cert_type, Unset):
            cert_type = UNSET
        else:
            cert_type = self.cert_type

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        issued_at: None | str | Unset
        if isinstance(self.issued_at, Unset):
            issued_at = UNSET
        else:
            issued_at = self.issued_at

        auto_renew: bool | None | Unset
        if isinstance(self.auto_renew, Unset):
            auto_renew = UNSET
        else:
            auto_renew = self.auto_renew

        actor: None | str | Unset
        if isinstance(self.actor, Unset):
            actor = UNSET
        else:
            actor = self.actor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "common_name": common_name,
                "expires_at": expires_at,
            }
        )
        if serial_number is not UNSET:
            field_dict["serial_number"] = serial_number
        if issuer is not UNSET:
            field_dict["issuer"] = issuer
        if subject_alt_names is not UNSET:
            field_dict["subject_alt_names"] = subject_alt_names
        if key_algorithm is not UNSET:
            field_dict["key_algorithm"] = key_algorithm
        if key_size is not UNSET:
            field_dict["key_size"] = key_size
        if cert_type is not UNSET:
            field_dict["cert_type"] = cert_type
        if status is not UNSET:
            field_dict["status"] = status
        if issued_at is not UNSET:
            field_dict["issued_at"] = issued_at
        if auto_renew is not UNSET:
            field_dict["auto_renew"] = auto_renew
        if actor is not UNSET:
            field_dict["actor"] = actor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        common_name = d.pop("common_name")

        expires_at = d.pop("expires_at")

        def _parse_serial_number(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        serial_number = _parse_serial_number(d.pop("serial_number", UNSET))

        def _parse_issuer(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        issuer = _parse_issuer(d.pop("issuer", UNSET))

        def _parse_subject_alt_names(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                subject_alt_names_type_0 = cast(list[str], data)

                return subject_alt_names_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        subject_alt_names = _parse_subject_alt_names(d.pop("subject_alt_names", UNSET))

        def _parse_key_algorithm(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        key_algorithm = _parse_key_algorithm(d.pop("key_algorithm", UNSET))

        def _parse_key_size(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        key_size = _parse_key_size(d.pop("key_size", UNSET))

        def _parse_cert_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cert_type = _parse_cert_type(d.pop("cert_type", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_issued_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        issued_at = _parse_issued_at(d.pop("issued_at", UNSET))

        def _parse_auto_renew(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        auto_renew = _parse_auto_renew(d.pop("auto_renew", UNSET))

        def _parse_actor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        actor = _parse_actor(d.pop("actor", UNSET))

        issue_certificate_request = cls(
            common_name=common_name,
            expires_at=expires_at,
            serial_number=serial_number,
            issuer=issuer,
            subject_alt_names=subject_alt_names,
            key_algorithm=key_algorithm,
            key_size=key_size,
            cert_type=cert_type,
            status=status,
            issued_at=issued_at,
            auto_renew=auto_renew,
            actor=actor,
        )

        issue_certificate_request.additional_properties = d
        return issue_certificate_request

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
