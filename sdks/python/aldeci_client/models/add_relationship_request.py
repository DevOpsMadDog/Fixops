from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.relationship_type import RelationshipType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.add_relationship_request_metadata import AddRelationshipRequestMetadata


T = TypeVar("T", bound="AddRelationshipRequest")


@_attrs_define
class AddRelationshipRequest:
    """
    Attributes:
        source_asset_id (str):
        target_asset_id (str):
        relationship_type (RelationshipType):
        org_id (str | Unset):  Default: 'default'.
        metadata (AddRelationshipRequestMetadata | Unset):
    """

    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    org_id: str | Unset = "default"
    metadata: AddRelationshipRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_asset_id = self.source_asset_id

        target_asset_id = self.target_asset_id

        relationship_type = self.relationship_type.value

        org_id = self.org_id

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_asset_id": source_asset_id,
                "target_asset_id": target_asset_id,
                "relationship_type": relationship_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_relationship_request_metadata import AddRelationshipRequestMetadata

        d = dict(src_dict)
        source_asset_id = d.pop("source_asset_id")

        target_asset_id = d.pop("target_asset_id")

        relationship_type = RelationshipType(d.pop("relationship_type"))

        org_id = d.pop("org_id", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: AddRelationshipRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AddRelationshipRequestMetadata.from_dict(_metadata)

        add_relationship_request = cls(
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            relationship_type=relationship_type,
            org_id=org_id,
            metadata=metadata,
        )

        add_relationship_request.additional_properties = d
        return add_relationship_request

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
