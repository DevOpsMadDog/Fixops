from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssetRegister")


@_attrs_define
class AssetRegister:
    """
    Attributes:
        asset_name (str): Human-readable asset name
        asset_id (None | str | Unset): Optional external asset ID
        asset_type (str | Unset): server | workstation | network | application | database | cloud | iot | mobile |
            container Default: 'server'.
        criticality (str | Unset): mission_critical | high | medium | low Default: 'medium'.
        owner (str | Unset):  Default: ''.
        environment (str | Unset):  Default: ''.
    """

    asset_name: str
    asset_id: None | str | Unset = UNSET
    asset_type: str | Unset = "server"
    criticality: str | Unset = "medium"
    owner: str | Unset = ""
    environment: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_name = self.asset_name

        asset_id: None | str | Unset
        if isinstance(self.asset_id, Unset):
            asset_id = UNSET
        else:
            asset_id = self.asset_id

        asset_type = self.asset_type

        criticality = self.criticality

        owner = self.owner

        environment = self.environment

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_name": asset_name,
            }
        )
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if asset_type is not UNSET:
            field_dict["asset_type"] = asset_type
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if owner is not UNSET:
            field_dict["owner"] = owner
        if environment is not UNSET:
            field_dict["environment"] = environment

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_name = d.pop("asset_name")

        def _parse_asset_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_id = _parse_asset_id(d.pop("asset_id", UNSET))

        asset_type = d.pop("asset_type", UNSET)

        criticality = d.pop("criticality", UNSET)

        owner = d.pop("owner", UNSET)

        environment = d.pop("environment", UNSET)

        asset_register = cls(
            asset_name=asset_name,
            asset_id=asset_id,
            asset_type=asset_type,
            criticality=criticality,
            owner=owner,
            environment=environment,
        )

        asset_register.additional_properties = d
        return asset_register

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
