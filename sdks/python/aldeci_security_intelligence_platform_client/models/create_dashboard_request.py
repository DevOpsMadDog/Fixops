from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateDashboardRequest")


@_attrs_define
class CreateDashboardRequest:
    """
    Attributes:
        name (str):
        description (str | Unset):  Default: ''.
        owner_email (str | Unset):  Default: 'unknown'.
        org_id (str | Unset):  Default: 'default'.
    """

    name: str
    description: str | Unset = ""
    owner_email: str | Unset = "unknown"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        owner_email = self.owner_email

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if owner_email is not UNSET:
            field_dict["owner_email"] = owner_email
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description", UNSET)

        owner_email = d.pop("owner_email", UNSET)

        org_id = d.pop("org_id", UNSET)

        create_dashboard_request = cls(
            name=name,
            description=description,
            owner_email=owner_email,
            org_id=org_id,
        )

        create_dashboard_request.additional_properties = d
        return create_dashboard_request

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
