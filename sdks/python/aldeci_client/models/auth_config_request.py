from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AuthConfigRequest")


@_attrs_define
class AuthConfigRequest:
    """
    Attributes:
        auth_type (str | Unset):  Default: 'none'.
        cookie_name (str | Unset):  Default: ''.
        cookie_value (str | Unset):  Default: ''.
        token (str | Unset):  Default: ''.
        header_name (str | Unset):  Default: 'Authorization'.
        token_url (str | Unset):  Default: ''.
        client_id (str | Unset):  Default: ''.
        client_secret (str | Unset):  Default: ''.
        scope (str | Unset):  Default: ''.
        username (str | Unset):  Default: ''.
        password (str | Unset):  Default: ''.
        login_url (str | Unset):  Default: ''.
        login_username_field (str | Unset):  Default: 'username'.
        login_password_field (str | Unset):  Default: 'password'.
    """

    auth_type: str | Unset = "none"
    cookie_name: str | Unset = ""
    cookie_value: str | Unset = ""
    token: str | Unset = ""
    header_name: str | Unset = "Authorization"
    token_url: str | Unset = ""
    client_id: str | Unset = ""
    client_secret: str | Unset = ""
    scope: str | Unset = ""
    username: str | Unset = ""
    password: str | Unset = ""
    login_url: str | Unset = ""
    login_username_field: str | Unset = "username"
    login_password_field: str | Unset = "password"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        auth_type = self.auth_type

        cookie_name = self.cookie_name

        cookie_value = self.cookie_value

        token = self.token

        header_name = self.header_name

        token_url = self.token_url

        client_id = self.client_id

        client_secret = self.client_secret

        scope = self.scope

        username = self.username

        password = self.password

        login_url = self.login_url

        login_username_field = self.login_username_field

        login_password_field = self.login_password_field

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if auth_type is not UNSET:
            field_dict["auth_type"] = auth_type
        if cookie_name is not UNSET:
            field_dict["cookie_name"] = cookie_name
        if cookie_value is not UNSET:
            field_dict["cookie_value"] = cookie_value
        if token is not UNSET:
            field_dict["token"] = token
        if header_name is not UNSET:
            field_dict["header_name"] = header_name
        if token_url is not UNSET:
            field_dict["token_url"] = token_url
        if client_id is not UNSET:
            field_dict["client_id"] = client_id
        if client_secret is not UNSET:
            field_dict["client_secret"] = client_secret
        if scope is not UNSET:
            field_dict["scope"] = scope
        if username is not UNSET:
            field_dict["username"] = username
        if password is not UNSET:
            field_dict["password"] = password
        if login_url is not UNSET:
            field_dict["login_url"] = login_url
        if login_username_field is not UNSET:
            field_dict["login_username_field"] = login_username_field
        if login_password_field is not UNSET:
            field_dict["login_password_field"] = login_password_field

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        auth_type = d.pop("auth_type", UNSET)

        cookie_name = d.pop("cookie_name", UNSET)

        cookie_value = d.pop("cookie_value", UNSET)

        token = d.pop("token", UNSET)

        header_name = d.pop("header_name", UNSET)

        token_url = d.pop("token_url", UNSET)

        client_id = d.pop("client_id", UNSET)

        client_secret = d.pop("client_secret", UNSET)

        scope = d.pop("scope", UNSET)

        username = d.pop("username", UNSET)

        password = d.pop("password", UNSET)

        login_url = d.pop("login_url", UNSET)

        login_username_field = d.pop("login_username_field", UNSET)

        login_password_field = d.pop("login_password_field", UNSET)

        auth_config_request = cls(
            auth_type=auth_type,
            cookie_name=cookie_name,
            cookie_value=cookie_value,
            token=token,
            header_name=header_name,
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            username=username,
            password=password,
            login_url=login_url,
            login_username_field=login_username_field,
            login_password_field=login_password_field,
        )

        auth_config_request.additional_properties = d
        return auth_config_request

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
