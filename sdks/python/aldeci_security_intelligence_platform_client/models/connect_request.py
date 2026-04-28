from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConnectRequest")


@_attrs_define
class ConnectRequest:
    """
    Attributes:
        instance_url (str): ServiceNow instance URL (e.g., https://dev12345.service-now.com)
        client_id (str | Unset): OAuth2 client ID Default: ''.
        client_secret (str | Unset): OAuth2 client secret Default: ''.
        username (str | Unset): Basic auth username (fallback) Default: ''.
        password (str | Unset): Basic auth password (fallback) Default: ''.
        auth_method (str | Unset): Auth method: oauth2 or basic Default: 'oauth2'.
    """

    instance_url: str
    client_id: str | Unset = ""
    client_secret: str | Unset = ""
    username: str | Unset = ""
    password: str | Unset = ""
    auth_method: str | Unset = "oauth2"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        instance_url = self.instance_url

        client_id = self.client_id

        client_secret = self.client_secret

        username = self.username

        password = self.password

        auth_method = self.auth_method

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "instance_url": instance_url,
            }
        )
        if client_id is not UNSET:
            field_dict["client_id"] = client_id
        if client_secret is not UNSET:
            field_dict["client_secret"] = client_secret
        if username is not UNSET:
            field_dict["username"] = username
        if password is not UNSET:
            field_dict["password"] = password
        if auth_method is not UNSET:
            field_dict["auth_method"] = auth_method

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        instance_url = d.pop("instance_url")

        client_id = d.pop("client_id", UNSET)

        client_secret = d.pop("client_secret", UNSET)

        username = d.pop("username", UNSET)

        password = d.pop("password", UNSET)

        auth_method = d.pop("auth_method", UNSET)

        connect_request = cls(
            instance_url=instance_url,
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
            auth_method=auth_method,
        )

        connect_request.additional_properties = d
        return connect_request

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
