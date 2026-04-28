from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TwinCreate")


@_attrs_define
class TwinCreate:
    """
    Attributes:
        name (str):
        twin_type (str | Unset):  Default: 'network'.
        description (str | Unset):  Default: ''.
        asset_count (int | Unset):  Default: 0.
        fidelity_level (str | Unset):  Default: 'medium'.
        sync_status (str | Unset):  Default: 'stale'.
    """

    name: str
    twin_type: str | Unset = "network"
    description: str | Unset = ""
    asset_count: int | Unset = 0
    fidelity_level: str | Unset = "medium"
    sync_status: str | Unset = "stale"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        twin_type = self.twin_type

        description = self.description

        asset_count = self.asset_count

        fidelity_level = self.fidelity_level

        sync_status = self.sync_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if twin_type is not UNSET:
            field_dict["twin_type"] = twin_type
        if description is not UNSET:
            field_dict["description"] = description
        if asset_count is not UNSET:
            field_dict["asset_count"] = asset_count
        if fidelity_level is not UNSET:
            field_dict["fidelity_level"] = fidelity_level
        if sync_status is not UNSET:
            field_dict["sync_status"] = sync_status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        twin_type = d.pop("twin_type", UNSET)

        description = d.pop("description", UNSET)

        asset_count = d.pop("asset_count", UNSET)

        fidelity_level = d.pop("fidelity_level", UNSET)

        sync_status = d.pop("sync_status", UNSET)

        twin_create = cls(
            name=name,
            twin_type=twin_type,
            description=description,
            asset_count=asset_count,
            fidelity_level=fidelity_level,
            sync_status=sync_status,
        )

        twin_create.additional_properties = d
        return twin_create

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
