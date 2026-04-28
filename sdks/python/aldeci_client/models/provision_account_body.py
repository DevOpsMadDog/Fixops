from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProvisionAccountBody")


@_attrs_define
class ProvisionAccountBody:
    """
    Attributes:
        username (str): Unique username for the account
        display_name (str | Unset): Human-readable display name Default: ''.
        email (str | Unset): Email address Default: ''.
        account_type (str | Unset): employee | contractor | service | system | bot | vendor | temp Default: 'employee'.
        department (str | Unset): Department or team Default: ''.
        manager (str | Unset): Manager username or ID Default: ''.
    """

    username: str
    display_name: str | Unset = ""
    email: str | Unset = ""
    account_type: str | Unset = "employee"
    department: str | Unset = ""
    manager: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        username = self.username

        display_name = self.display_name

        email = self.email

        account_type = self.account_type

        department = self.department

        manager = self.manager

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "username": username,
            }
        )
        if display_name is not UNSET:
            field_dict["display_name"] = display_name
        if email is not UNSET:
            field_dict["email"] = email
        if account_type is not UNSET:
            field_dict["account_type"] = account_type
        if department is not UNSET:
            field_dict["department"] = department
        if manager is not UNSET:
            field_dict["manager"] = manager

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        username = d.pop("username")

        display_name = d.pop("display_name", UNSET)

        email = d.pop("email", UNSET)

        account_type = d.pop("account_type", UNSET)

        department = d.pop("department", UNSET)

        manager = d.pop("manager", UNSET)

        provision_account_body = cls(
            username=username,
            display_name=display_name,
            email=email,
            account_type=account_type,
            department=department,
            manager=manager,
        )

        provision_account_body.additional_properties = d
        return provision_account_body

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
