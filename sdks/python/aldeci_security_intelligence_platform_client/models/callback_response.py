from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CallbackResponse")


@_attrs_define
class CallbackResponse:
    """
    Attributes:
        access_token (str):
        email (str):
        name (str):
        roles (list[str]):
        groups (list[str]):
        provider (str):
        token_type (str | Unset):  Default: 'Bearer'.
    """

    access_token: str
    email: str
    name: str
    roles: list[str]
    groups: list[str]
    provider: str
    token_type: str | Unset = "Bearer"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        access_token = self.access_token

        email = self.email

        name = self.name

        roles = self.roles

        groups = self.groups

        provider = self.provider

        token_type = self.token_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "access_token": access_token,
                "email": email,
                "name": name,
                "roles": roles,
                "groups": groups,
                "provider": provider,
            }
        )
        if token_type is not UNSET:
            field_dict["token_type"] = token_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        access_token = d.pop("access_token")

        email = d.pop("email")

        name = d.pop("name")

        roles = cast(list[str], d.pop("roles"))

        groups = cast(list[str], d.pop("groups"))

        provider = d.pop("provider")

        token_type = d.pop("token_type", UNSET)

        callback_response = cls(
            access_token=access_token,
            email=email,
            name=name,
            roles=roles,
            groups=groups,
            provider=provider,
            token_type=token_type,
        )

        callback_response.additional_properties = d
        return callback_response

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
