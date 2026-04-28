from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KeyCreateRequest")


@_attrs_define
class KeyCreateRequest:
    """Request to create a new API key.

    Attributes:
        name (str):
        user_id (str):
        role (str | Unset):  Default: 'viewer'.
        scopes (list[Any] | Unset):
        ttl_days (int | None | Unset):
    """

    name: str
    user_id: str
    role: str | Unset = "viewer"
    scopes: list[Any] | Unset = UNSET
    ttl_days: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        user_id = self.user_id

        role = self.role

        scopes: list[Any] | Unset = UNSET
        if not isinstance(self.scopes, Unset):
            scopes = self.scopes

        ttl_days: int | None | Unset
        if isinstance(self.ttl_days, Unset):
            ttl_days = UNSET
        else:
            ttl_days = self.ttl_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "user_id": user_id,
            }
        )
        if role is not UNSET:
            field_dict["role"] = role
        if scopes is not UNSET:
            field_dict["scopes"] = scopes
        if ttl_days is not UNSET:
            field_dict["ttl_days"] = ttl_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        user_id = d.pop("user_id")

        role = d.pop("role", UNSET)

        scopes = cast(list[Any], d.pop("scopes", UNSET))

        def _parse_ttl_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        ttl_days = _parse_ttl_days(d.pop("ttl_days", UNSET))

        key_create_request = cls(
            name=name,
            user_id=user_id,
            role=role,
            scopes=scopes,
            ttl_days=ttl_days,
        )

        key_create_request.additional_properties = d
        return key_create_request

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
