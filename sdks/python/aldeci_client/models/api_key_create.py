from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ApiKeyCreate")


@_attrs_define
class ApiKeyCreate:
    """
    Attributes:
        key_name (str):
        owner_id (str | Unset):  Default: ''.
        scopes (list[str] | Unset):
        rate_limit_per_hour (int | Unset):  Default: 1000.
        expires_at (None | str | Unset):
    """

    key_name: str
    owner_id: str | Unset = ""
    scopes: list[str] | Unset = UNSET
    rate_limit_per_hour: int | Unset = 1000
    expires_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        key_name = self.key_name

        owner_id = self.owner_id

        scopes: list[str] | Unset = UNSET
        if not isinstance(self.scopes, Unset):
            scopes = self.scopes

        rate_limit_per_hour = self.rate_limit_per_hour

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "key_name": key_name,
            }
        )
        if owner_id is not UNSET:
            field_dict["owner_id"] = owner_id
        if scopes is not UNSET:
            field_dict["scopes"] = scopes
        if rate_limit_per_hour is not UNSET:
            field_dict["rate_limit_per_hour"] = rate_limit_per_hour
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        key_name = d.pop("key_name")

        owner_id = d.pop("owner_id", UNSET)

        scopes = cast(list[str], d.pop("scopes", UNSET))

        rate_limit_per_hour = d.pop("rate_limit_per_hour", UNSET)

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        api_key_create = cls(
            key_name=key_name,
            owner_id=owner_id,
            scopes=scopes,
            rate_limit_per_hour=rate_limit_per_hour,
            expires_at=expires_at,
        )

        api_key_create.additional_properties = d
        return api_key_create

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
