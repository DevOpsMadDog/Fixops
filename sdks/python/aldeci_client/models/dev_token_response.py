from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dev_token_user import DevTokenUser


T = TypeVar("T", bound="DevTokenResponse")


@_attrs_define
class DevTokenResponse:
    """Response from /api/v1/auth/dev-token.

    Attributes:
        access_token (str):
        user (DevTokenUser): User identity bundled with dev-minted token.
        token_type (str | Unset):  Default: 'Bearer'.
        expires_in (int | Unset):  Default: 3600.
    """

    access_token: str
    user: DevTokenUser
    token_type: str | Unset = "Bearer"
    expires_in: int | Unset = 3600
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        access_token = self.access_token

        user = self.user.to_dict()

        token_type = self.token_type

        expires_in = self.expires_in

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "access_token": access_token,
                "user": user,
            }
        )
        if token_type is not UNSET:
            field_dict["token_type"] = token_type
        if expires_in is not UNSET:
            field_dict["expires_in"] = expires_in

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dev_token_user import DevTokenUser

        d = dict(src_dict)
        access_token = d.pop("access_token")

        user = DevTokenUser.from_dict(d.pop("user"))

        token_type = d.pop("token_type", UNSET)

        expires_in = d.pop("expires_in", UNSET)

        dev_token_response = cls(
            access_token=access_token,
            user=user,
            token_type=token_type,
            expires_in=expires_in,
        )

        dev_token_response.additional_properties = d
        return dev_token_response

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
