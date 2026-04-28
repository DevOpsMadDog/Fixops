from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KeyCreateResponse")


@_attrs_define
class KeyCreateResponse:
    """Response from key creation — includes the plaintext key (shown ONCE).

    Attributes:
        id (str):
        key_prefix (str):
        name (str):
        user_id (str):
        role (str):
        scopes (list[Any]):
        is_active (bool):
        created_at (str):
        plaintext_key (str):
        expires_at (None | str | Unset):
        rotated_at (None | str | Unset):
        revoked_at (None | str | Unset):
        last_used_at (None | str | Unset):
        predecessor_id (None | str | Unset):
    """

    id: str
    key_prefix: str
    name: str
    user_id: str
    role: str
    scopes: list[Any]
    is_active: bool
    created_at: str
    plaintext_key: str
    expires_at: None | str | Unset = UNSET
    rotated_at: None | str | Unset = UNSET
    revoked_at: None | str | Unset = UNSET
    last_used_at: None | str | Unset = UNSET
    predecessor_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        key_prefix = self.key_prefix

        name = self.name

        user_id = self.user_id

        role = self.role

        scopes = self.scopes

        is_active = self.is_active

        created_at = self.created_at

        plaintext_key = self.plaintext_key

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        rotated_at: None | str | Unset
        if isinstance(self.rotated_at, Unset):
            rotated_at = UNSET
        else:
            rotated_at = self.rotated_at

        revoked_at: None | str | Unset
        if isinstance(self.revoked_at, Unset):
            revoked_at = UNSET
        else:
            revoked_at = self.revoked_at

        last_used_at: None | str | Unset
        if isinstance(self.last_used_at, Unset):
            last_used_at = UNSET
        else:
            last_used_at = self.last_used_at

        predecessor_id: None | str | Unset
        if isinstance(self.predecessor_id, Unset):
            predecessor_id = UNSET
        else:
            predecessor_id = self.predecessor_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "key_prefix": key_prefix,
                "name": name,
                "user_id": user_id,
                "role": role,
                "scopes": scopes,
                "is_active": is_active,
                "created_at": created_at,
                "plaintext_key": plaintext_key,
            }
        )
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if rotated_at is not UNSET:
            field_dict["rotated_at"] = rotated_at
        if revoked_at is not UNSET:
            field_dict["revoked_at"] = revoked_at
        if last_used_at is not UNSET:
            field_dict["last_used_at"] = last_used_at
        if predecessor_id is not UNSET:
            field_dict["predecessor_id"] = predecessor_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        key_prefix = d.pop("key_prefix")

        name = d.pop("name")

        user_id = d.pop("user_id")

        role = d.pop("role")

        scopes = cast(list[Any], d.pop("scopes"))

        is_active = d.pop("is_active")

        created_at = d.pop("created_at")

        plaintext_key = d.pop("plaintext_key")

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        def _parse_rotated_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        rotated_at = _parse_rotated_at(d.pop("rotated_at", UNSET))

        def _parse_revoked_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        revoked_at = _parse_revoked_at(d.pop("revoked_at", UNSET))

        def _parse_last_used_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_used_at = _parse_last_used_at(d.pop("last_used_at", UNSET))

        def _parse_predecessor_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        predecessor_id = _parse_predecessor_id(d.pop("predecessor_id", UNSET))

        key_create_response = cls(
            id=id,
            key_prefix=key_prefix,
            name=name,
            user_id=user_id,
            role=role,
            scopes=scopes,
            is_active=is_active,
            created_at=created_at,
            plaintext_key=plaintext_key,
            expires_at=expires_at,
            rotated_at=rotated_at,
            revoked_at=revoked_at,
            last_used_at=last_used_at,
            predecessor_id=predecessor_id,
        )

        key_create_response.additional_properties = d
        return key_create_response

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
