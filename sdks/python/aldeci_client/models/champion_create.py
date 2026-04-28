from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChampionCreate")


@_attrs_define
class ChampionCreate:
    """
    Attributes:
        name (str):
        email (str | Unset):  Default: ''.
        department (str | Unset):  Default: ''.
        team (str | Unset):  Default: ''.
        role (str | Unset):  Default: 'champion'.
        status (str | Unset):  Default: 'active'.
        joined_at (None | str | Unset):
    """

    name: str
    email: str | Unset = ""
    department: str | Unset = ""
    team: str | Unset = ""
    role: str | Unset = "champion"
    status: str | Unset = "active"
    joined_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        email = self.email

        department = self.department

        team = self.team

        role = self.role

        status = self.status

        joined_at: None | str | Unset
        if isinstance(self.joined_at, Unset):
            joined_at = UNSET
        else:
            joined_at = self.joined_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if email is not UNSET:
            field_dict["email"] = email
        if department is not UNSET:
            field_dict["department"] = department
        if team is not UNSET:
            field_dict["team"] = team
        if role is not UNSET:
            field_dict["role"] = role
        if status is not UNSET:
            field_dict["status"] = status
        if joined_at is not UNSET:
            field_dict["joined_at"] = joined_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        email = d.pop("email", UNSET)

        department = d.pop("department", UNSET)

        team = d.pop("team", UNSET)

        role = d.pop("role", UNSET)

        status = d.pop("status", UNSET)

        def _parse_joined_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        joined_at = _parse_joined_at(d.pop("joined_at", UNSET))

        champion_create = cls(
            name=name,
            email=email,
            department=department,
            team=team,
            role=role,
            status=status,
            joined_at=joined_at,
        )

        champion_create.additional_properties = d
        return champion_create

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
