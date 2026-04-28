from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.user_role import UserRole
from ..models.user_status import UserStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="UserUpdate")


@_attrs_define
class UserUpdate:
    """Request model for updating a user.

    Attributes:
        first_name (None | str | Unset):
        last_name (None | str | Unset):
        role (None | Unset | UserRole):
        status (None | Unset | UserStatus):
        department (None | str | Unset):
    """

    first_name: None | str | Unset = UNSET
    last_name: None | str | Unset = UNSET
    role: None | Unset | UserRole = UNSET
    status: None | Unset | UserStatus = UNSET
    department: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        first_name: None | str | Unset
        if isinstance(self.first_name, Unset):
            first_name = UNSET
        else:
            first_name = self.first_name

        last_name: None | str | Unset
        if isinstance(self.last_name, Unset):
            last_name = UNSET
        else:
            last_name = self.last_name

        role: None | str | Unset
        if isinstance(self.role, Unset):
            role = UNSET
        elif isinstance(self.role, UserRole):
            role = self.role.value
        else:
            role = self.role

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        elif isinstance(self.status, UserStatus):
            status = self.status.value
        else:
            status = self.status

        department: None | str | Unset
        if isinstance(self.department, Unset):
            department = UNSET
        else:
            department = self.department

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if first_name is not UNSET:
            field_dict["first_name"] = first_name
        if last_name is not UNSET:
            field_dict["last_name"] = last_name
        if role is not UNSET:
            field_dict["role"] = role
        if status is not UNSET:
            field_dict["status"] = status
        if department is not UNSET:
            field_dict["department"] = department

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_first_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_name = _parse_first_name(d.pop("first_name", UNSET))

        def _parse_last_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_name = _parse_last_name(d.pop("last_name", UNSET))

        def _parse_role(data: object) -> None | Unset | UserRole:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                role_type_0 = UserRole(data)

                return role_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UserRole, data)

        role = _parse_role(d.pop("role", UNSET))

        def _parse_status(data: object) -> None | Unset | UserStatus:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                status_type_0 = UserStatus(data)

                return status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UserStatus, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_department(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        department = _parse_department(d.pop("department", UNSET))

        user_update = cls(
            first_name=first_name,
            last_name=last_name,
            role=role,
            status=status,
            department=department,
        )

        user_update.additional_properties = d
        return user_update

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
