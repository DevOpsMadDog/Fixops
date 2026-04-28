from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddMemberRequest")


@_attrs_define
class AddMemberRequest:
    """
    Attributes:
        asset_id (str):
        asset_type (str):
        added_by (str | Unset):  Default: ''.
    """

    asset_id: str
    asset_type: str
    added_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        asset_type = self.asset_type

        added_by = self.added_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
                "asset_type": asset_type,
            }
        )
        if added_by is not UNSET:
            field_dict["added_by"] = added_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        asset_type = d.pop("asset_type")

        added_by = d.pop("added_by", UNSET)

        add_member_request = cls(
            asset_id=asset_id,
            asset_type=asset_type,
            added_by=added_by,
        )

        add_member_request.additional_properties = d
        return add_member_request

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
