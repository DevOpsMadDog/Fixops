from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateKeyRequest")


@_attrs_define
class CreateKeyRequest:
    """
    Attributes:
        name (str):
        org_id (str):
        role (str | Unset):  Default: 'viewer'.
        scopes (list[str] | Unset):
        expires_at (datetime.datetime | None | Unset):
        rate_limit (int | Unset):  Default: 60.
        description (str | Unset):  Default: ''.
    """

    name: str
    org_id: str
    role: str | Unset = "viewer"
    scopes: list[str] | Unset = UNSET
    expires_at: datetime.datetime | None | Unset = UNSET
    rate_limit: int | Unset = 60
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_id = self.org_id

        role = self.role

        scopes: list[str] | Unset = UNSET
        if not isinstance(self.scopes, Unset):
            scopes = self.scopes

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        elif isinstance(self.expires_at, datetime.datetime):
            expires_at = self.expires_at.isoformat()
        else:
            expires_at = self.expires_at

        rate_limit = self.rate_limit

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "org_id": org_id,
            }
        )
        if role is not UNSET:
            field_dict["role"] = role
        if scopes is not UNSET:
            field_dict["scopes"] = scopes
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if rate_limit is not UNSET:
            field_dict["rate_limit"] = rate_limit
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        org_id = d.pop("org_id")

        role = d.pop("role", UNSET)

        scopes = cast(list[str], d.pop("scopes", UNSET))

        def _parse_expires_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                expires_at_type_0 = isoparse(data)

                return expires_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        rate_limit = d.pop("rate_limit", UNSET)

        description = d.pop("description", UNSET)

        create_key_request = cls(
            name=name,
            org_id=org_id,
            role=role,
            scopes=scopes,
            expires_at=expires_at,
            rate_limit=rate_limit,
            description=description,
        )

        create_key_request.additional_properties = d
        return create_key_request

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
