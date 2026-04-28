from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.user_role import UserRole
from ..types import UNSET, Unset

T = TypeVar("T", bound="UserCreate")


@_attrs_define
class UserCreate:
    """Request model for creating a user.

    Attributes:
        email (str): User email
        password (str): User password
        first_name (str):
        last_name (str):
        role (UserRole | Unset): User roles for RBAC.
        department (None | str | Unset):
    """

    email: str
    password: str
    first_name: str
    last_name: str
    role: UserRole | Unset = UNSET
    department: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        password = self.password

        first_name = self.first_name

        last_name = self.last_name

        role: str | Unset = UNSET
        if not isinstance(self.role, Unset):
            role = self.role.value

        department: None | str | Unset
        if isinstance(self.department, Unset):
            department = UNSET
        else:
            department = self.department

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "email": email,
                "password": password,
                "first_name": first_name,
                "last_name": last_name,
            }
        )
        if role is not UNSET:
            field_dict["role"] = role
        if department is not UNSET:
            field_dict["department"] = department

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email = d.pop("email")

        password = d.pop("password")

        first_name = d.pop("first_name")

        last_name = d.pop("last_name")

        _role = d.pop("role", UNSET)
        role: UserRole | Unset
        if isinstance(_role, Unset):
            role = UNSET
        else:
            role = UserRole(_role)

        def _parse_department(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        department = _parse_department(d.pop("department", UNSET))

        user_create = cls(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role=role,
            department=department,
        )

        user_create.additional_properties = d
        return user_create

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
