from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.asset_type import AssetType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.network_asset_metadata import NetworkAssetMetadata


T = TypeVar("T", bound="NetworkAsset")


@_attrs_define
class NetworkAsset:
    """
    Attributes:
        org_id (str):
        asset_type (AssetType):
        name (str):
        address (str):
        id (str | Unset):
        vlan_id (int | None | Unset):
        description (None | str | Unset):
        tags (list[str] | Unset):
        discovered_at (datetime.datetime | Unset):
        last_seen (datetime.datetime | Unset):
        metadata (NetworkAssetMetadata | Unset):
    """

    org_id: str
    asset_type: AssetType
    name: str
    address: str
    id: str | Unset = UNSET
    vlan_id: int | None | Unset = UNSET
    description: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    discovered_at: datetime.datetime | Unset = UNSET
    last_seen: datetime.datetime | Unset = UNSET
    metadata: NetworkAssetMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        asset_type = self.asset_type.value

        name = self.name

        address = self.address

        id = self.id

        vlan_id: int | None | Unset
        if isinstance(self.vlan_id, Unset):
            vlan_id = UNSET
        else:
            vlan_id = self.vlan_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        discovered_at: str | Unset = UNSET
        if not isinstance(self.discovered_at, Unset):
            discovered_at = self.discovered_at.isoformat()

        last_seen: str | Unset = UNSET
        if not isinstance(self.last_seen, Unset):
            last_seen = self.last_seen.isoformat()

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "asset_type": asset_type,
                "name": name,
                "address": address,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if vlan_id is not UNSET:
            field_dict["vlan_id"] = vlan_id
        if description is not UNSET:
            field_dict["description"] = description
        if tags is not UNSET:
            field_dict["tags"] = tags
        if discovered_at is not UNSET:
            field_dict["discovered_at"] = discovered_at
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.network_asset_metadata import NetworkAssetMetadata

        d = dict(src_dict)
        org_id = d.pop("org_id")

        asset_type = AssetType(d.pop("asset_type"))

        name = d.pop("name")

        address = d.pop("address")

        id = d.pop("id", UNSET)

        def _parse_vlan_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        vlan_id = _parse_vlan_id(d.pop("vlan_id", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        tags = cast(list[str], d.pop("tags", UNSET))

        _discovered_at = d.pop("discovered_at", UNSET)
        discovered_at: datetime.datetime | Unset
        if isinstance(_discovered_at, Unset):
            discovered_at = UNSET
        else:
            discovered_at = isoparse(_discovered_at)

        _last_seen = d.pop("last_seen", UNSET)
        last_seen: datetime.datetime | Unset
        if isinstance(_last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = isoparse(_last_seen)

        _metadata = d.pop("metadata", UNSET)
        metadata: NetworkAssetMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = NetworkAssetMetadata.from_dict(_metadata)

        network_asset = cls(
            org_id=org_id,
            asset_type=asset_type,
            name=name,
            address=address,
            id=id,
            vlan_id=vlan_id,
            description=description,
            tags=tags,
            discovered_at=discovered_at,
            last_seen=last_seen,
            metadata=metadata,
        )

        network_asset.additional_properties = d
        return network_asset

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
