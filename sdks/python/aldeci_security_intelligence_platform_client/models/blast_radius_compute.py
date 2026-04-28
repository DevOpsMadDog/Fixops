from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BlastRadiusCompute")


@_attrs_define
class BlastRadiusCompute:
    """
    Attributes:
        org_id (str):
        asset_ref (str):
        max_hops (int | Unset):  Default: 3.
    """

    org_id: str
    asset_ref: str
    max_hops: int | Unset = 3
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        asset_ref = self.asset_ref

        max_hops = self.max_hops

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "asset_ref": asset_ref,
            }
        )
        if max_hops is not UNSET:
            field_dict["max_hops"] = max_hops

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        asset_ref = d.pop("asset_ref")

        max_hops = d.pop("max_hops", UNSET)

        blast_radius_compute = cls(
            org_id=org_id,
            asset_ref=asset_ref,
            max_hops=max_hops,
        )

        blast_radius_compute.additional_properties = d
        return blast_radius_compute

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
