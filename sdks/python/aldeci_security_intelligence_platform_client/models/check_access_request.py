from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.resource_type import ResourceType
from ..types import UNSET, Unset

T = TypeVar("T", bound="CheckAccessRequest")


@_attrs_define
class CheckAccessRequest:
    """
    Attributes:
        user_role (str):
        resource_type (ResourceType): Resource types managed by the access matrix.
        resource_id (None | str | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    user_role: str
    resource_type: ResourceType
    resource_id: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_role = self.user_role

        resource_type = self.resource_type.value

        resource_id: None | str | Unset
        if isinstance(self.resource_id, Unset):
            resource_id = UNSET
        else:
            resource_id = self.resource_id

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_role": user_role,
                "resource_type": resource_type,
            }
        )
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_role = d.pop("user_role")

        resource_type = ResourceType(d.pop("resource_type"))

        def _parse_resource_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        resource_id = _parse_resource_id(d.pop("resource_id", UNSET))

        org_id = d.pop("org_id", UNSET)

        check_access_request = cls(
            user_role=user_role,
            resource_type=resource_type,
            resource_id=resource_id,
            org_id=org_id,
        )

        check_access_request.additional_properties = d
        return check_access_request

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
