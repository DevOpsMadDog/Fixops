from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GrantEntitlementRequest")


@_attrs_define
class GrantEntitlementRequest:
    """
    Attributes:
        user_id (str): User to grant access to
        resource_id (str): Resource identifier
        resource_type (str): application | database | server | network | cloud-service | api | data-store | vault
        access_level (str): read | write | admin | execute | delete | full-control
        granted_by (str | Unset): Approver username Default: ''.
        expires_at (None | str | Unset): ISO 8601 expiry timestamp (optional)
    """

    user_id: str
    resource_id: str
    resource_type: str
    access_level: str
    granted_by: str | Unset = ""
    expires_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        resource_id = self.resource_id

        resource_type = self.resource_type

        access_level = self.access_level

        granted_by = self.granted_by

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "access_level": access_level,
            }
        )
        if granted_by is not UNSET:
            field_dict["granted_by"] = granted_by
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        resource_id = d.pop("resource_id")

        resource_type = d.pop("resource_type")

        access_level = d.pop("access_level")

        granted_by = d.pop("granted_by", UNSET)

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        grant_entitlement_request = cls(
            user_id=user_id,
            resource_id=resource_id,
            resource_type=resource_type,
            access_level=access_level,
            granted_by=granted_by,
            expires_at=expires_at,
        )

        grant_entitlement_request.additional_properties = d
        return grant_entitlement_request

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
