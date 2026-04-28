from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DevTokenRequest")


@_attrs_define
class DevTokenRequest:
    """Request body for /api/v1/auth/dev-token.

    Attributes:
        org_id (str | Unset):  Default: 'default'.
        role (str | Unset):  Default: 'admin'.
        email (str | Unset):  Default: 'dev@verify'.
    """

    org_id: str | Unset = "default"
    role: str | Unset = "admin"
    email: str | Unset = "dev@verify"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        role = self.role

        email = self.email

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if role is not UNSET:
            field_dict["role"] = role
        if email is not UNSET:
            field_dict["email"] = email

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        role = d.pop("role", UNSET)

        email = d.pop("email", UNSET)

        dev_token_request = cls(
            org_id=org_id,
            role=role,
            email=email,
        )

        dev_token_request.additional_properties = d
        return dev_token_request

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
