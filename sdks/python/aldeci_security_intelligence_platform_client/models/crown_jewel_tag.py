from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CrownJewelTag")


@_attrs_define
class CrownJewelTag:
    """
    Attributes:
        org_id (str):
        asset_ref (str):
        reason (str | Unset):  Default: ''.
    """

    org_id: str
    asset_ref: str
    reason: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        asset_ref = self.asset_ref

        reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "asset_ref": asset_ref,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        asset_ref = d.pop("asset_ref")

        reason = d.pop("reason", UNSET)

        crown_jewel_tag = cls(
            org_id=org_id,
            asset_ref=asset_ref,
            reason=reason,
        )

        crown_jewel_tag.additional_properties = d
        return crown_jewel_tag

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
