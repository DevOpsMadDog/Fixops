from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.neighborhood_response_entities_item import NeighborhoodResponseEntitiesItem
    from ..models.neighborhood_response_relationships_item import NeighborhoodResponseRelationshipsItem


T = TypeVar("T", bound="NeighborhoodResponse")


@_attrs_define
class NeighborhoodResponse:
    """Response from /entities/{entity_id}/neighborhood.

    Attributes:
        entity_id (str):
        entities (list[NeighborhoodResponseEntitiesItem]):
        relationships (list[NeighborhoodResponseRelationshipsItem]):
    """

    entity_id: str
    entities: list[NeighborhoodResponseEntitiesItem]
    relationships: list[NeighborhoodResponseRelationshipsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_id = self.entity_id

        entities = []
        for entities_item_data in self.entities:
            entities_item = entities_item_data.to_dict()
            entities.append(entities_item)

        relationships = []
        for relationships_item_data in self.relationships:
            relationships_item = relationships_item_data.to_dict()
            relationships.append(relationships_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_id": entity_id,
                "entities": entities,
                "relationships": relationships,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.neighborhood_response_entities_item import NeighborhoodResponseEntitiesItem
        from ..models.neighborhood_response_relationships_item import NeighborhoodResponseRelationshipsItem

        d = dict(src_dict)
        entity_id = d.pop("entity_id")

        entities = []
        _entities = d.pop("entities")
        for entities_item_data in _entities:
            entities_item = NeighborhoodResponseEntitiesItem.from_dict(entities_item_data)

            entities.append(entities_item)

        relationships = []
        _relationships = d.pop("relationships")
        for relationships_item_data in _relationships:
            relationships_item = NeighborhoodResponseRelationshipsItem.from_dict(relationships_item_data)

            relationships.append(relationships_item)

        neighborhood_response = cls(
            entity_id=entity_id,
            entities=entities,
            relationships=relationships,
        )

        neighborhood_response.additional_properties = d
        return neighborhood_response

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
