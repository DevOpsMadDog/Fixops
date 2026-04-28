from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.login_response_user import LoginResponseUser


T = TypeVar("T", bound="LoginResponse")


@_attrs_define
class LoginResponse:
    """Login response with JWT token.

    Attributes:
        access_token (str):
        user (LoginResponseUser):
        token_type (str | Unset):  Default: 'bearer'.
    """

    access_token: str
    user: LoginResponseUser
    token_type: str | Unset = "bearer"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        access_token = self.access_token

        user = self.user.to_dict()

        token_type = self.token_type

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

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.login_response_user import LoginResponseUser

        d = dict(src_dict)
        access_token = d.pop("access_token")

        user = LoginResponseUser.from_dict(d.pop("user"))

        token_type = d.pop("token_type", UNSET)

        login_response = cls(
            access_token=access_token,
            user=user,
            token_type=token_type,
        )

        login_response.additional_properties = d
        return login_response

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
