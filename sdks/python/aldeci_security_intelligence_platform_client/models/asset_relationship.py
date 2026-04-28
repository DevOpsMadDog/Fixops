from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.relationship_type import RelationshipType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.asset_relationship_metadata import AssetRelationshipMetadata


T = TypeVar("T", bound="AssetRelationship")


@_attrs_define
class AssetRelationship:
    """Directed relationship between two assets.

    Attributes:
        source_asset_id (str):
        target_asset_id (str):
        relationship_type (RelationshipType):
        id (str | Unset):
        metadata (AssetRelationshipMetadata | Unset):
        created_at (str | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    id: str | Unset = UNSET
    metadata: AssetRelationshipMetadata | Unset = UNSET
    created_at: str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_asset_id = self.source_asset_id

        target_asset_id = self.target_asset_id

        relationship_type = self.relationship_type.value

        id = self.id

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        created_at = self.created_at

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_asset_id": source_asset_id,
                "target_asset_id": target_asset_id,
                "relationship_type": relationship_type,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.asset_relationship_metadata import AssetRelationshipMetadata

        d = dict(src_dict)
        source_asset_id = d.pop("source_asset_id")

        target_asset_id = d.pop("target_asset_id")

        relationship_type = RelationshipType(d.pop("relationship_type"))

        id = d.pop("id", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: AssetRelationshipMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AssetRelationshipMetadata.from_dict(_metadata)

        created_at = d.pop("created_at", UNSET)

        org_id = d.pop("org_id", UNSET)

        asset_relationship = cls(
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            relationship_type=relationship_type,
            id=id,
            metadata=metadata,
            created_at=created_at,
            org_id=org_id,
        )

        asset_relationship.additional_properties = d
        return asset_relationship

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
