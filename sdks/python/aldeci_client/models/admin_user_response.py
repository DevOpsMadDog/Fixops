from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AdminUserResponse")


@_attrs_define
class AdminUserResponse:
    """Response model for a user.

    Attributes:
        id (str):
        email (str):
        first_name (str):
        last_name (str):
        role (str):
        status (str):
        department (None | str):
        created_at (str):
        updated_at (str):
        last_login_at (None | str):
    """

    id: str
    email: str
    first_name: str
    last_name: str
    role: str
    status: str
    department: None | str
    created_at: str
    updated_at: str
    last_login_at: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        email = self.email

        first_name = self.first_name

        last_name = self.last_name

        role = self.role

        status = self.status

        department: None | str
        department = self.department

        created_at = self.created_at

        updated_at = self.updated_at

        last_login_at: None | str
        last_login_at = self.last_login_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "role": role,
                "status": status,
                "department": department,
                "created_at": created_at,
                "updated_at": updated_at,
                "last_login_at": last_login_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        email = d.pop("email")

        first_name = d.pop("first_name")

        last_name = d.pop("last_name")

        role = d.pop("role")

        status = d.pop("status")

        def _parse_department(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        department = _parse_department(d.pop("department"))

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        def _parse_last_login_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        last_login_at = _parse_last_login_at(d.pop("last_login_at"))

        admin_user_response = cls(
            id=id,
            email=email,
            first_name=first_name,
            last_name=last_name,
            role=role,
            status=status,
            department=department,
            created_at=created_at,
            updated_at=updated_at,
            last_login_at=last_login_at,
        )

        admin_user_response.additional_properties = d
        return admin_user_response

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
