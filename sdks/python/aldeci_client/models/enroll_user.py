from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrollUser")


@_attrs_define
class EnrollUser:
    """
    Attributes:
        user_id (str):
        user_name (str | Unset):  Default: ''.
        department (str | Unset):  Default: ''.
    """

    user_id: str
    user_name: str | Unset = ""
    department: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        user_name = self.user_name

        department = self.department

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
            }
        )
        if user_name is not UNSET:
            field_dict["user_name"] = user_name
        if department is not UNSET:
            field_dict["department"] = department

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        user_name = d.pop("user_name", UNSET)

        department = d.pop("department", UNSET)

        enroll_user = cls(
            user_id=user_id,
            user_name=user_name,
            department=department,
        )

        enroll_user.additional_properties = d
        return enroll_user

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
