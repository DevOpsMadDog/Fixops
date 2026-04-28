from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TeamCreate")


@_attrs_define
class TeamCreate:
    """
    Attributes:
        name (str):
        team_type (str | Unset):  Default: 'blue'.
        department (str | Unset):  Default: ''.
    """

    name: str
    team_type: str | Unset = "blue"
    department: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        team_type = self.team_type

        department = self.department

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if team_type is not UNSET:
            field_dict["team_type"] = team_type
        if department is not UNSET:
            field_dict["department"] = department

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        team_type = d.pop("team_type", UNSET)

        department = d.pop("department", UNSET)

        team_create = cls(
            name=name,
            team_type=team_type,
            department=department,
        )

        team_create.additional_properties = d
        return team_create

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
