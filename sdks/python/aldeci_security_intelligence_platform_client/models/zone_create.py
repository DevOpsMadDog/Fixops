from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ZoneCreate")


@_attrs_define
class ZoneCreate:
    """
    Attributes:
        zone_type (str):
        zone_name (str | Unset):  Default: ''.
        asset_count (int | Unset):  Default: 0.
        security_level (str | Unset):  Default: 'sl1'.
        purdue_level (int | Unset):  Default: 0.
        conduit_count (int | Unset):  Default: 0.
    """

    zone_type: str
    zone_name: str | Unset = ""
    asset_count: int | Unset = 0
    security_level: str | Unset = "sl1"
    purdue_level: int | Unset = 0
    conduit_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        zone_type = self.zone_type

        zone_name = self.zone_name

        asset_count = self.asset_count

        security_level = self.security_level

        purdue_level = self.purdue_level

        conduit_count = self.conduit_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "zone_type": zone_type,
            }
        )
        if zone_name is not UNSET:
            field_dict["zone_name"] = zone_name
        if asset_count is not UNSET:
            field_dict["asset_count"] = asset_count
        if security_level is not UNSET:
            field_dict["security_level"] = security_level
        if purdue_level is not UNSET:
            field_dict["purdue_level"] = purdue_level
        if conduit_count is not UNSET:
            field_dict["conduit_count"] = conduit_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        zone_type = d.pop("zone_type")

        zone_name = d.pop("zone_name", UNSET)

        asset_count = d.pop("asset_count", UNSET)

        security_level = d.pop("security_level", UNSET)

        purdue_level = d.pop("purdue_level", UNSET)

        conduit_count = d.pop("conduit_count", UNSET)

        zone_create = cls(
            zone_type=zone_type,
            zone_name=zone_name,
            asset_count=asset_count,
            security_level=security_level,
            purdue_level=purdue_level,
            conduit_count=conduit_count,
        )

        zone_create.additional_properties = d
        return zone_create

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
