from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReachabilityRequest")


@_attrs_define
class ReachabilityRequest:
    """Request for reachability analysis.

    Attributes:
        cve_id (str):
        asset_ids (list[str]):
        depth (str | Unset): shallow, medium, deep Default: 'deep'.
    """

    cve_id: str
    asset_ids: list[str]
    depth: str | Unset = "deep"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        asset_ids = self.asset_ids

        depth = self.depth

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "asset_ids": asset_ids,
            }
        )
        if depth is not UNSET:
            field_dict["depth"] = depth

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        asset_ids = cast(list[str], d.pop("asset_ids"))

        depth = d.pop("depth", UNSET)

        reachability_request = cls(
            cve_id=cve_id,
            asset_ids=asset_ids,
            depth=depth,
        )

        reachability_request.additional_properties = d
        return reachability_request

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
