from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AccountCreate")


@_attrs_define
class AccountCreate:
    """
    Attributes:
        username (str):
        account_type (str | Unset):  Default: 'service'.
        system (str | Unset):  Default: ''.
        owner (str | Unset):  Default: ''.
        justification (str | Unset):  Default: ''.
    """

    username: str
    account_type: str | Unset = "service"
    system: str | Unset = ""
    owner: str | Unset = ""
    justification: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        username = self.username

        account_type = self.account_type

        system = self.system

        owner = self.owner

        justification = self.justification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "username": username,
            }
        )
        if account_type is not UNSET:
            field_dict["account_type"] = account_type
        if system is not UNSET:
            field_dict["system"] = system
        if owner is not UNSET:
            field_dict["owner"] = owner
        if justification is not UNSET:
            field_dict["justification"] = justification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        username = d.pop("username")

        account_type = d.pop("account_type", UNSET)

        system = d.pop("system", UNSET)

        owner = d.pop("owner", UNSET)

        justification = d.pop("justification", UNSET)

        account_create = cls(
            username=username,
            account_type=account_type,
            system=system,
            owner=owner,
            justification=justification,
        )

        account_create.additional_properties = d
        return account_create

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
