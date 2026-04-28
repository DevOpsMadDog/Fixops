from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BlastRadiusRequest")


@_attrs_define
class BlastRadiusRequest:
    """
    Attributes:
        node_id (str): Node to calculate blast radius for
        max_hops (int | Unset):  Default: 3.
    """

    node_id: str
    max_hops: int | Unset = 3
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        node_id = self.node_id

        max_hops = self.max_hops

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "node_id": node_id,
            }
        )
        if max_hops is not UNSET:
            field_dict["max_hops"] = max_hops

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        node_id = d.pop("node_id")

        max_hops = d.pop("max_hops", UNSET)

        blast_radius_request = cls(
            node_id=node_id,
            max_hops=max_hops,
        )

        blast_radius_request.additional_properties = d
        return blast_radius_request

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
