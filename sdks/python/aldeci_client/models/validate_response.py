from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ValidateResponse")


@_attrs_define
class ValidateResponse:
    """
    Attributes:
        ok (bool):
        message (str):
        provider (str):
        account_id (str):
    """

    ok: bool
    message: str
    provider: str
    account_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ok = self.ok

        message = self.message

        provider = self.provider

        account_id = self.account_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ok": ok,
                "message": message,
                "provider": provider,
                "account_id": account_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ok = d.pop("ok")

        message = d.pop("message")

        provider = d.pop("provider")

        account_id = d.pop("account_id")

        validate_response = cls(
            ok=ok,
            message=message,
            provider=provider,
            account_id=account_id,
        )

        validate_response.additional_properties = d
        return validate_response

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
