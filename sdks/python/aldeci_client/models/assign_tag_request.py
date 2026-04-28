from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssignTagRequest")


@_attrs_define
class AssignTagRequest:
    """
    Attributes:
        tag_id (str): ID of the tag to assign
        assigned_by (str | Unset):  Default: 'system'.
    """

    tag_id: str
    assigned_by: str | Unset = "system"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tag_id = self.tag_id

        assigned_by = self.assigned_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tag_id": tag_id,
            }
        )
        if assigned_by is not UNSET:
            field_dict["assigned_by"] = assigned_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tag_id = d.pop("tag_id")

        assigned_by = d.pop("assigned_by", UNSET)

        assign_tag_request = cls(
            tag_id=tag_id,
            assigned_by=assigned_by,
        )

        assign_tag_request.additional_properties = d
        return assign_tag_request

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
