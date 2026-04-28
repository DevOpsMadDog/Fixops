from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IngestAssetRequest")


@_attrs_define
class IngestAssetRequest:
    """Validated asset ingest request.

    Attributes:
        asset_id (str):
        org_id (None | str | Unset):
        name (None | str | Unset):
        asset_type (None | str | Unset):
    """

    asset_id: str
    org_id: None | str | Unset = UNSET
    name: None | str | Unset = UNSET
    asset_type: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        asset_type: None | str | Unset
        if isinstance(self.asset_type, Unset):
            asset_type = UNSET
        else:
            asset_type = self.asset_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if name is not UNSET:
            field_dict["name"] = name
        if asset_type is not UNSET:
            field_dict["asset_type"] = asset_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_asset_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_type = _parse_asset_type(d.pop("asset_type", UNSET))

        ingest_asset_request = cls(
            asset_id=asset_id,
            org_id=org_id,
            name=name,
            asset_type=asset_type,
        )

        ingest_asset_request.additional_properties = d
        return ingest_asset_request

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
