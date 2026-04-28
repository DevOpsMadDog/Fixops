from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ChangeCreate")


@_attrs_define
class ChangeCreate:
    """
    Attributes:
        endpoint_id (str):
        change_type (str):
        org_id (str | Unset):  Default: 'default'.
        change_description (str | Unset):  Default: ''.
    """

    endpoint_id: str
    change_type: str
    org_id: str | Unset = "default"
    change_description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        endpoint_id = self.endpoint_id

        change_type = self.change_type

        org_id = self.org_id

        change_description = self.change_description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "endpoint_id": endpoint_id,
                "change_type": change_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if change_description is not UNSET:
            field_dict["change_description"] = change_description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        endpoint_id = d.pop("endpoint_id")

        change_type = d.pop("change_type")

        org_id = d.pop("org_id", UNSET)

        change_description = d.pop("change_description", UNSET)

        change_create = cls(
            endpoint_id=endpoint_id,
            change_type=change_type,
            org_id=org_id,
            change_description=change_description,
        )

        change_create.additional_properties = d
        return change_create

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
