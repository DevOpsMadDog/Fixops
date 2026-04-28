from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.entity_response_entity import EntityResponseEntity
    from ..models.entity_response_relationships_item import EntityResponseRelationshipsItem


T = TypeVar("T", bound="EntityResponse")


@_attrs_define
class EntityResponse:
    """Entity with relationships.

    Attributes:
        entity (EntityResponseEntity):
        relationships (list[EntityResponseRelationshipsItem]):
        relationship_count (int):
    """

    entity: EntityResponseEntity
    relationships: list[EntityResponseRelationshipsItem]
    relationship_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity = self.entity.to_dict()

        relationships = []
        for relationships_item_data in self.relationships:
            relationships_item = relationships_item_data.to_dict()
            relationships.append(relationships_item)

        relationship_count = self.relationship_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity": entity,
                "relationships": relationships,
                "relationship_count": relationship_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.entity_response_entity import EntityResponseEntity
        from ..models.entity_response_relationships_item import EntityResponseRelationshipsItem

        d = dict(src_dict)
        entity = EntityResponseEntity.from_dict(d.pop("entity"))

        relationships = []
        _relationships = d.pop("relationships")
        for relationships_item_data in _relationships:
            relationships_item = EntityResponseRelationshipsItem.from_dict(relationships_item_data)

            relationships.append(relationships_item)

        relationship_count = d.pop("relationship_count")

        entity_response = cls(
            entity=entity,
            relationships=relationships,
            relationship_count=relationship_count,
        )

        entity_response.additional_properties = d
        return entity_response

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
