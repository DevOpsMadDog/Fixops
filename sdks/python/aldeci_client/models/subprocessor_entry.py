from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SubprocessorEntry")


@_attrs_define
class SubprocessorEntry:
    """A sub-processor (third-party vendor) used by the organization.

    Attributes:
        name (str):
        purpose (str):
        location (str):
        id (str | Unset):
        data_types (list[str] | Unset):
        org_id (str | Unset):  Default: ''.
    """

    name: str
    purpose: str
    location: str
    id: str | Unset = UNSET
    data_types: list[str] | Unset = UNSET
    org_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        purpose = self.purpose

        location = self.location

        id = self.id

        data_types: list[str] | Unset = UNSET
        if not isinstance(self.data_types, Unset):
            data_types = self.data_types

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "purpose": purpose,
                "location": location,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if data_types is not UNSET:
            field_dict["data_types"] = data_types
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        purpose = d.pop("purpose")

        location = d.pop("location")

        id = d.pop("id", UNSET)

        data_types = cast(list[str], d.pop("data_types", UNSET))

        org_id = d.pop("org_id", UNSET)

        subprocessor_entry = cls(
            name=name,
            purpose=purpose,
            location=location,
            id=id,
            data_types=data_types,
            org_id=org_id,
        )

        subprocessor_entry.additional_properties = d
        return subprocessor_entry

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
