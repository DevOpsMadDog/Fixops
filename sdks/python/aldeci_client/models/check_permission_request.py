from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CheckPermissionRequest")


@_attrs_define
class CheckPermissionRequest:
    """
    Attributes:
        user_id (str): User identifier
        org_id (str): Organisation identifier
        scope (str): Scope/permission string to check
    """

    user_id: str
    org_id: str
    scope: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        org_id = self.org_id

        scope = self.scope

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "org_id": org_id,
                "scope": scope,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        org_id = d.pop("org_id")

        scope = d.pop("scope")

        check_permission_request = cls(
            user_id=user_id,
            org_id=org_id,
            scope=scope,
        )

        check_permission_request.additional_properties = d
        return check_permission_request

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
