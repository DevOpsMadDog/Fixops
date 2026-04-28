from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GrantAccessBody")


@_attrs_define
class GrantAccessBody:
    """
    Attributes:
        system_name (str): Target system name
        role (str): Role to grant
        access_level (str | Unset): read | write | admin | owner Default: 'read'.
        expires_at (str | Unset): ISO datetime for expiry (empty = never) Default: ''.
        granted_by (str | Unset): Approver username or ID Default: ''.
    """

    system_name: str
    role: str
    access_level: str | Unset = "read"
    expires_at: str | Unset = ""
    granted_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        system_name = self.system_name

        role = self.role

        access_level = self.access_level

        expires_at = self.expires_at

        granted_by = self.granted_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "system_name": system_name,
                "role": role,
            }
        )
        if access_level is not UNSET:
            field_dict["access_level"] = access_level
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if granted_by is not UNSET:
            field_dict["granted_by"] = granted_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        system_name = d.pop("system_name")

        role = d.pop("role")

        access_level = d.pop("access_level", UNSET)

        expires_at = d.pop("expires_at", UNSET)

        granted_by = d.pop("granted_by", UNSET)

        grant_access_body = cls(
            system_name=system_name,
            role=role,
            access_level=access_level,
            expires_at=expires_at,
            granted_by=granted_by,
        )

        grant_access_body.additional_properties = d
        return grant_access_body

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
