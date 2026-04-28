from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateGroupRequest")


@_attrs_define
class CreateGroupRequest:
    """
    Attributes:
        group_name (str):
        group_type (str | Unset):  Default: 'functional'.
        description (str | Unset):  Default: ''.
        owner (str | Unset):  Default: ''.
        criticality (str | Unset):  Default: 'medium'.
    """

    group_name: str
    group_type: str | Unset = "functional"
    description: str | Unset = ""
    owner: str | Unset = ""
    criticality: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        group_name = self.group_name

        group_type = self.group_type

        description = self.description

        owner = self.owner

        criticality = self.criticality

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "group_name": group_name,
            }
        )
        if group_type is not UNSET:
            field_dict["group_type"] = group_type
        if description is not UNSET:
            field_dict["description"] = description
        if owner is not UNSET:
            field_dict["owner"] = owner
        if criticality is not UNSET:
            field_dict["criticality"] = criticality

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        group_name = d.pop("group_name")

        group_type = d.pop("group_type", UNSET)

        description = d.pop("description", UNSET)

        owner = d.pop("owner", UNSET)

        criticality = d.pop("criticality", UNSET)

        create_group_request = cls(
            group_name=group_name,
            group_type=group_type,
            description=description,
            owner=owner,
            criticality=criticality,
        )

        create_group_request.additional_properties = d
        return create_group_request

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
