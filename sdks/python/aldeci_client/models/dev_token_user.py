from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="DevTokenUser")


@_attrs_define
class DevTokenUser:
    """User identity bundled with dev-minted token.

    Attributes:
        sub (str):
        email (str):
        role (str):
        org_id (str):
        scopes (list[str]):
    """

    sub: str
    email: str
    role: str
    org_id: str
    scopes: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sub = self.sub

        email = self.email

        role = self.role

        org_id = self.org_id

        scopes = self.scopes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sub": sub,
                "email": email,
                "role": role,
                "org_id": org_id,
                "scopes": scopes,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        sub = d.pop("sub")

        email = d.pop("email")

        role = d.pop("role")

        org_id = d.pop("org_id")

        scopes = cast(list[str], d.pop("scopes"))

        dev_token_user = cls(
            sub=sub,
            email=email,
            role=role,
            org_id=org_id,
            scopes=scopes,
        )

        dev_token_user.additional_properties = d
        return dev_token_user

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
