from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="DisposableTokenCreate")


@_attrs_define
class DisposableTokenCreate:
    """Request to mint a disposable scoped token.

    Attributes:
        scope (list[str]):
        ttl_seconds (int):
        purpose (str):
    """

    scope: list[str]
    ttl_seconds: int
    purpose: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scope = self.scope

        ttl_seconds = self.ttl_seconds

        purpose = self.purpose

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scope": scope,
                "ttl_seconds": ttl_seconds,
                "purpose": purpose,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scope = cast(list[str], d.pop("scope"))

        ttl_seconds = d.pop("ttl_seconds")

        purpose = d.pop("purpose")

        disposable_token_create = cls(
            scope=scope,
            ttl_seconds=ttl_seconds,
            purpose=purpose,
        )

        disposable_token_create.additional_properties = d
        return disposable_token_create

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
