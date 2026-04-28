from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BodyTokenApiV1Oauth2TokenPost")


@_attrs_define
class BodyTokenApiV1Oauth2TokenPost:
    """
    Attributes:
        client_id (str): API Key ID (ak_…)
        client_secret (str): Raw API key (aldeci_…)
        grant_type (None | str | Unset): Must be 'client_credentials' if provided
    """

    client_id: str
    client_secret: str
    grant_type: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        client_id = self.client_id

        client_secret = self.client_secret

        grant_type: None | str | Unset
        if isinstance(self.grant_type, Unset):
            grant_type = UNSET
        else:
            grant_type = self.grant_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "client_id": client_id,
                "client_secret": client_secret,
            }
        )
        if grant_type is not UNSET:
            field_dict["grant_type"] = grant_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        client_id = d.pop("client_id")

        client_secret = d.pop("client_secret")

        def _parse_grant_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        grant_type = _parse_grant_type(d.pop("grant_type", UNSET))

        body_token_api_v1_oauth_2_token_post = cls(
            client_id=client_id,
            client_secret=client_secret,
            grant_type=grant_type,
        )

        body_token_api_v1_oauth_2_token_post.additional_properties = d
        return body_token_api_v1_oauth_2_token_post

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
