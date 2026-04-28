from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CheckAccessResponse")


@_attrs_define
class CheckAccessResponse:
    """
    Attributes:
        user_role (str):
        resource_type (str):
        resource_id (None | str):
        access_level (str):
        granted (bool):
        org_id (str):
    """

    user_role: str
    resource_type: str
    resource_id: None | str
    access_level: str
    granted: bool
    org_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_role = self.user_role

        resource_type = self.resource_type

        resource_id: None | str
        resource_id = self.resource_id

        access_level = self.access_level

        granted = self.granted

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_role": user_role,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "access_level": access_level,
                "granted": granted,
                "org_id": org_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_role = d.pop("user_role")

        resource_type = d.pop("resource_type")

        def _parse_resource_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        resource_id = _parse_resource_id(d.pop("resource_id"))

        access_level = d.pop("access_level")

        granted = d.pop("granted")

        org_id = d.pop("org_id")

        check_access_response = cls(
            user_role=user_role,
            resource_type=resource_type,
            resource_id=resource_id,
            access_level=access_level,
            granted=granted,
            org_id=org_id,
        )

        check_access_response.additional_properties = d
        return check_access_response

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
