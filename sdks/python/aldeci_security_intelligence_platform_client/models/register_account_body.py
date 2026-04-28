from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterAccountBody")


@_attrs_define
class RegisterAccountBody:
    """
    Attributes:
        username (str): Account username
        account_type (str | Unset): service_account | admin | root | domain_admin | database_admin | application_account
            | shared Default: 'admin'.
        system_name (str | Unset): Target system name Default: ''.
        department (str | Unset): Owning department Default: ''.
        owner (str | Unset): Account owner Default: ''.
        mfa_enabled (bool | Unset): MFA status Default: False.
    """

    username: str
    account_type: str | Unset = "admin"
    system_name: str | Unset = ""
    department: str | Unset = ""
    owner: str | Unset = ""
    mfa_enabled: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        username = self.username

        account_type = self.account_type

        system_name = self.system_name

        department = self.department

        owner = self.owner

        mfa_enabled = self.mfa_enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "username": username,
            }
        )
        if account_type is not UNSET:
            field_dict["account_type"] = account_type
        if system_name is not UNSET:
            field_dict["system_name"] = system_name
        if department is not UNSET:
            field_dict["department"] = department
        if owner is not UNSET:
            field_dict["owner"] = owner
        if mfa_enabled is not UNSET:
            field_dict["mfa_enabled"] = mfa_enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        username = d.pop("username")

        account_type = d.pop("account_type", UNSET)

        system_name = d.pop("system_name", UNSET)

        department = d.pop("department", UNSET)

        owner = d.pop("owner", UNSET)

        mfa_enabled = d.pop("mfa_enabled", UNSET)

        register_account_body = cls(
            username=username,
            account_type=account_type,
            system_name=system_name,
            department=department,
            owner=owner,
            mfa_enabled=mfa_enabled,
        )

        register_account_body.additional_properties = d
        return register_account_body

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
