from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttackPathRequest")


@_attrs_define
class AttackPathRequest:
    """Request for attack path analysis.

    Attributes:
        asset_id (str):
        depth (int | Unset):  Default: 3.
        include_lateral (bool | Unset):  Default: True.
    """

    asset_id: str
    depth: int | Unset = 3
    include_lateral: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        depth = self.depth

        include_lateral = self.include_lateral

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
            }
        )
        if depth is not UNSET:
            field_dict["depth"] = depth
        if include_lateral is not UNSET:
            field_dict["include_lateral"] = include_lateral

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        depth = d.pop("depth", UNSET)

        include_lateral = d.pop("include_lateral", UNSET)

        attack_path_request = cls(
            asset_id=asset_id,
            depth=depth,
            include_lateral=include_lateral,
        )

        attack_path_request.additional_properties = d
        return attack_path_request

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
