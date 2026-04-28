from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssetAdd")


@_attrs_define
class AssetAdd:
    """
    Attributes:
        asset_name (str):
        asset_type (str | Unset):  Default: ''.
    """

    asset_name: str
    asset_type: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_name = self.asset_name

        asset_type = self.asset_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_name": asset_name,
            }
        )
        if asset_type is not UNSET:
            field_dict["asset_type"] = asset_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_name = d.pop("asset_name")

        asset_type = d.pop("asset_type", UNSET)

        asset_add = cls(
            asset_name=asset_name,
            asset_type=asset_type,
        )

        asset_add.additional_properties = d
        return asset_add

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
