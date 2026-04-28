from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateRoleRequest")


@_attrs_define
class CreateRoleRequest:
    """
    Attributes:
        role_name (str): Unique role name
        role_type (str): business | technical | privileged | service-account | emergency
        permissions (list[str] | Unset): List of permission strings
        owner (str | Unset): Role owner Default: ''.
        risk_level (str | Unset): critical | high | medium | low Default: 'medium'.
    """

    role_name: str
    role_type: str
    permissions: list[str] | Unset = UNSET
    owner: str | Unset = ""
    risk_level: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        role_name = self.role_name

        role_type = self.role_type

        permissions: list[str] | Unset = UNSET
        if not isinstance(self.permissions, Unset):
            permissions = self.permissions

        owner = self.owner

        risk_level = self.risk_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "role_name": role_name,
                "role_type": role_type,
            }
        )
        if permissions is not UNSET:
            field_dict["permissions"] = permissions
        if owner is not UNSET:
            field_dict["owner"] = owner
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        role_name = d.pop("role_name")

        role_type = d.pop("role_type")

        permissions = cast(list[str], d.pop("permissions", UNSET))

        owner = d.pop("owner", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        create_role_request = cls(
            role_name=role_name,
            role_type=role_type,
            permissions=permissions,
            owner=owner,
            risk_level=risk_level,
        )

        create_role_request.additional_properties = d
        return create_role_request

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
