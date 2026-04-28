from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterAccountRequest")


@_attrs_define
class RegisterAccountRequest:
    """
    Attributes:
        provider (str | Unset):  Default: 'aws'.
        account_id (str | Unset):  Default: ''.
        account_name (str | Unset):  Default: ''.
        region (str | Unset):  Default: 'us-east-1'.
        environment (str | Unset):  Default: 'prod'.
    """

    provider: str | Unset = "aws"
    account_id: str | Unset = ""
    account_name: str | Unset = ""
    region: str | Unset = "us-east-1"
    environment: str | Unset = "prod"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        provider = self.provider

        account_id = self.account_id

        account_name = self.account_name

        region = self.region

        environment = self.environment

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if provider is not UNSET:
            field_dict["provider"] = provider
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if account_name is not UNSET:
            field_dict["account_name"] = account_name
        if region is not UNSET:
            field_dict["region"] = region
        if environment is not UNSET:
            field_dict["environment"] = environment

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        provider = d.pop("provider", UNSET)

        account_id = d.pop("account_id", UNSET)

        account_name = d.pop("account_name", UNSET)

        region = d.pop("region", UNSET)

        environment = d.pop("environment", UNSET)

        register_account_request = cls(
            provider=provider,
            account_id=account_id,
            account_name=account_name,
            region=region,
            environment=environment,
        )

        register_account_request.additional_properties = d
        return register_account_request

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
