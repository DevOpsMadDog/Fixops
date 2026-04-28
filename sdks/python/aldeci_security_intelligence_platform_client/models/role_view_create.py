from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RoleViewCreate")


@_attrs_define
class RoleViewCreate:
    """Request to switch role view.

    Attributes:
        target_role (str):
        duration_seconds (int | Unset):  Default: 3600.
    """

    target_role: str
    duration_seconds: int | Unset = 3600
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_role = self.target_role

        duration_seconds = self.duration_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target_role": target_role,
            }
        )
        if duration_seconds is not UNSET:
            field_dict["duration_seconds"] = duration_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target_role = d.pop("target_role")

        duration_seconds = d.pop("duration_seconds", UNSET)

        role_view_create = cls(
            target_role=target_role,
            duration_seconds=duration_seconds,
        )

        role_view_create.additional_properties = d
        return role_view_create

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
