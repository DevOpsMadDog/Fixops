from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="DisposableTokenCreateResponse")


@_attrs_define
class DisposableTokenCreateResponse:
    """Disposable token mint response — raw_token returned ONCE.

    Attributes:
        token_id (str):
        raw_token (str):
        expires_at (str):
        scope (list[str]):
    """

    token_id: str
    raw_token: str
    expires_at: str
    scope: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        token_id = self.token_id

        raw_token = self.raw_token

        expires_at = self.expires_at

        scope = self.scope

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "token_id": token_id,
                "raw_token": raw_token,
                "expires_at": expires_at,
                "scope": scope,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        token_id = d.pop("token_id")

        raw_token = d.pop("raw_token")

        expires_at = d.pop("expires_at")

        scope = cast(list[str], d.pop("scope"))

        disposable_token_create_response = cls(
            token_id=token_id,
            raw_token=raw_token,
            expires_at=expires_at,
            scope=scope,
        )

        disposable_token_create_response.additional_properties = d
        return disposable_token_create_response

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
