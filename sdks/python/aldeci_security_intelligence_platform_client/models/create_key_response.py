from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

T = TypeVar("T", bound="CreateKeyResponse")


@_attrs_define
class CreateKeyResponse:
    """One-time creation response that includes the plaintext key.

    Attributes:
        id (str):
        name (str):
        prefix (str):
        org_id (str):
        created_by (str):
        created_at (datetime.datetime):
        expires_at (datetime.datetime | None):
        last_used_at (datetime.datetime | None):
        use_count (int):
        rate_limit (int):
        scopes (list[str]):
        role (str):
        is_active (bool):
        description (str):
        raw_key (str): Store this securely — shown only once
    """

    id: str
    name: str
    prefix: str
    org_id: str
    created_by: str
    created_at: datetime.datetime
    expires_at: datetime.datetime | None
    last_used_at: datetime.datetime | None
    use_count: int
    rate_limit: int
    scopes: list[str]
    role: str
    is_active: bool
    description: str
    raw_key: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        prefix = self.prefix

        org_id = self.org_id

        created_by = self.created_by

        created_at = self.created_at.isoformat()

        expires_at: None | str
        if isinstance(self.expires_at, datetime.datetime):
            expires_at = self.expires_at.isoformat()
        else:
            expires_at = self.expires_at

        last_used_at: None | str
        if isinstance(self.last_used_at, datetime.datetime):
            last_used_at = self.last_used_at.isoformat()
        else:
            last_used_at = self.last_used_at

        use_count = self.use_count

        rate_limit = self.rate_limit

        scopes = self.scopes

        role = self.role

        is_active = self.is_active

        description = self.description

        raw_key = self.raw_key

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "prefix": prefix,
                "org_id": org_id,
                "created_by": created_by,
                "created_at": created_at,
                "expires_at": expires_at,
                "last_used_at": last_used_at,
                "use_count": use_count,
                "rate_limit": rate_limit,
                "scopes": scopes,
                "role": role,
                "is_active": is_active,
                "description": description,
                "raw_key": raw_key,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        prefix = d.pop("prefix")

        org_id = d.pop("org_id")

        created_by = d.pop("created_by")

        created_at = isoparse(d.pop("created_at"))

        def _parse_expires_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                expires_at_type_0 = isoparse(data)

                return expires_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        expires_at = _parse_expires_at(d.pop("expires_at"))

        def _parse_last_used_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_used_at_type_0 = isoparse(data)

                return last_used_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        last_used_at = _parse_last_used_at(d.pop("last_used_at"))

        use_count = d.pop("use_count")

        rate_limit = d.pop("rate_limit")

        scopes = cast(list[str], d.pop("scopes"))

        role = d.pop("role")

        is_active = d.pop("is_active")

        description = d.pop("description")

        raw_key = d.pop("raw_key")

        create_key_response = cls(
            id=id,
            name=name,
            prefix=prefix,
            org_id=org_id,
            created_by=created_by,
            created_at=created_at,
            expires_at=expires_at,
            last_used_at=last_used_at,
            use_count=use_count,
            rate_limit=rate_limit,
            scopes=scopes,
            role=role,
            is_active=is_active,
            description=description,
            raw_key=raw_key,
        )

        create_key_response.additional_properties = d
        return create_key_response

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
