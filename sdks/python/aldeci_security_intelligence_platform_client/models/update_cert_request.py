from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateCertRequest")


@_attrs_define
class UpdateCertRequest:
    """
    Attributes:
        domain (None | str | Unset):
        issuer (None | str | Unset):
        serial (None | str | Unset):
        not_before (None | str | Unset):
        not_after (None | str | Unset):
        algorithm (None | str | Unset):
        key_size (int | None | Unset):
        san_list (list[str] | None | Unset):
        wildcard (bool | None | Unset):
        self_signed (bool | None | Unset):
    """

    domain: None | str | Unset = UNSET
    issuer: None | str | Unset = UNSET
    serial: None | str | Unset = UNSET
    not_before: None | str | Unset = UNSET
    not_after: None | str | Unset = UNSET
    algorithm: None | str | Unset = UNSET
    key_size: int | None | Unset = UNSET
    san_list: list[str] | None | Unset = UNSET
    wildcard: bool | None | Unset = UNSET
    self_signed: bool | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain: None | str | Unset
        if isinstance(self.domain, Unset):
            domain = UNSET
        else:
            domain = self.domain

        issuer: None | str | Unset
        if isinstance(self.issuer, Unset):
            issuer = UNSET
        else:
            issuer = self.issuer

        serial: None | str | Unset
        if isinstance(self.serial, Unset):
            serial = UNSET
        else:
            serial = self.serial

        not_before: None | str | Unset
        if isinstance(self.not_before, Unset):
            not_before = UNSET
        else:
            not_before = self.not_before

        not_after: None | str | Unset
        if isinstance(self.not_after, Unset):
            not_after = UNSET
        else:
            not_after = self.not_after

        algorithm: None | str | Unset
        if isinstance(self.algorithm, Unset):
            algorithm = UNSET
        else:
            algorithm = self.algorithm

        key_size: int | None | Unset
        if isinstance(self.key_size, Unset):
            key_size = UNSET
        else:
            key_size = self.key_size

        san_list: list[str] | None | Unset
        if isinstance(self.san_list, Unset):
            san_list = UNSET
        elif isinstance(self.san_list, list):
            san_list = self.san_list

        else:
            san_list = self.san_list

        wildcard: bool | None | Unset
        if isinstance(self.wildcard, Unset):
            wildcard = UNSET
        else:
            wildcard = self.wildcard

        self_signed: bool | None | Unset
        if isinstance(self.self_signed, Unset):
            self_signed = UNSET
        else:
            self_signed = self.self_signed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if domain is not UNSET:
            field_dict["domain"] = domain
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
        if self_signed is not UNSET:
            field_dict["self_signed"] = self_signed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_domain(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        domain = _parse_domain(d.pop("domain", UNSET))

        def _parse_issuer(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        issuer = _parse_issuer(d.pop("issuer", UNSET))

        def _parse_serial(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        serial = _parse_serial(d.pop("serial", UNSET))

        def _parse_not_before(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        not_before = _parse_not_before(d.pop("not_before", UNSET))

        def _parse_not_after(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        not_after = _parse_not_after(d.pop("not_after", UNSET))

        def _parse_algorithm(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        algorithm = _parse_algorithm(d.pop("algorithm", UNSET))

        def _parse_key_size(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        key_size = _parse_key_size(d.pop("key_size", UNSET))

        def _parse_san_list(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                san_list_type_0 = cast(list[str], data)

                return san_list_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        san_list = _parse_san_list(d.pop("san_list", UNSET))

        def _parse_wildcard(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        wildcard = _parse_wildcard(d.pop("wildcard", UNSET))

        def _parse_self_signed(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        self_signed = _parse_self_signed(d.pop("self_signed", UNSET))

        update_cert_request = cls(
            domain=domain,
            issuer=issuer,
            serial=serial,
            not_before=not_before,
            not_after=not_after,
            algorithm=algorithm,
            key_size=key_size,
            san_list=san_list,
            wildcard=wildcard,
            self_signed=self_signed,
        )

        update_cert_request.additional_properties = d
        return update_cert_request

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
