from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RotationRecord")


@_attrs_define
class RotationRecord:
    """
    Attributes:
        rotation_type (str | Unset): manual|automated|emergency Default: 'manual'.
        performed_by (str | Unset): User or system that performed rotation Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    rotation_type: str | Unset = "manual"
    performed_by: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rotation_type = self.rotation_type

        performed_by = self.performed_by

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if rotation_type is not UNSET:
            field_dict["rotation_type"] = rotation_type
        if performed_by is not UNSET:
            field_dict["performed_by"] = performed_by
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rotation_type = d.pop("rotation_type", UNSET)

        performed_by = d.pop("performed_by", UNSET)

        org_id = d.pop("org_id", UNSET)

        rotation_record = cls(
            rotation_type=rotation_type,
            performed_by=performed_by,
            org_id=org_id,
        )

        rotation_record.additional_properties = d
        return rotation_record

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
