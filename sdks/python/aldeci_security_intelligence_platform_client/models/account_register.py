from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AccountRegister")


@_attrs_define
class AccountRegister:
    """
    Attributes:
        account_id (str):
        account_name (str):
        provider (str):
        region (str | Unset):  Default: ''.
    """

    account_id: str
    account_name: str
    provider: str
    region: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        account_id = self.account_id

        account_name = self.account_name

        provider = self.provider

        region = self.region

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "account_id": account_id,
                "account_name": account_name,
                "provider": provider,
            }
        )
        if region is not UNSET:
            field_dict["region"] = region

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        account_id = d.pop("account_id")

        account_name = d.pop("account_name")

        provider = d.pop("provider")

        region = d.pop("region", UNSET)

        account_register = cls(
            account_id=account_id,
            account_name=account_name,
            provider=provider,
            region=region,
        )

        account_register.additional_properties = d
        return account_register

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
