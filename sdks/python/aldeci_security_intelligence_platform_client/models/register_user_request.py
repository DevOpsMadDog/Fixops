from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterUserRequest")


@_attrs_define
class RegisterUserRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        username (str): Unique username within the org
        department (str | Unset): User's department Default: ''.
        role (str | Unset): User's job role Default: ''.
        manager (str | Unset): Manager's username or ID Default: ''.
        status (str | Unset): active | suspended | terminated Default: 'active'.
        last_seen (None | str | Unset): ISO-8601 datetime of last activity
    """

    org_id: str
    username: str
    department: str | Unset = ""
    role: str | Unset = ""
    manager: str | Unset = ""
    status: str | Unset = "active"
    last_seen: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        username = self.username

        department = self.department

        role = self.role

        manager = self.manager

        status = self.status

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "username": username,
            }
        )
        if department is not UNSET:
            field_dict["department"] = department
        if role is not UNSET:
            field_dict["role"] = role
        if manager is not UNSET:
            field_dict["manager"] = manager
        if status is not UNSET:
            field_dict["status"] = status
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        username = d.pop("username")

        department = d.pop("department", UNSET)

        role = d.pop("role", UNSET)

        manager = d.pop("manager", UNSET)

        status = d.pop("status", UNSET)

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        register_user_request = cls(
            org_id=org_id,
            username=username,
            department=department,
            role=role,
            manager=manager,
            status=status,
            last_seen=last_seen,
        )

        register_user_request.additional_properties = d
        return register_user_request

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
