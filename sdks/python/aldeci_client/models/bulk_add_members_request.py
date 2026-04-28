from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkAddMembersRequest")


@_attrs_define
class BulkAddMembersRequest:
    """
    Attributes:
        asset_ids (list[str]):
        asset_type (str):
        added_by (str | Unset):  Default: ''.
    """

    asset_ids: list[str]
    asset_type: str
    added_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_ids = self.asset_ids

        asset_type = self.asset_type

        added_by = self.added_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_ids": asset_ids,
                "asset_type": asset_type,
            }
        )
        if added_by is not UNSET:
            field_dict["added_by"] = added_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_ids = cast(list[str], d.pop("asset_ids"))

        asset_type = d.pop("asset_type")

        added_by = d.pop("added_by", UNSET)

        bulk_add_members_request = cls(
            asset_ids=asset_ids,
            asset_type=asset_type,
            added_by=added_by,
        )

        bulk_add_members_request.additional_properties = d
        return bulk_add_members_request

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
