from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.retrieve_response_entities_item import RetrieveResponseEntitiesItem
    from ..models.retrieve_response_relationships_item import RetrieveResponseRelationshipsItem


T = TypeVar("T", bound="RetrieveResponse")


@_attrs_define
class RetrieveResponse:
    """Response from /retrieve.

    Attributes:
        query (str):
        entities (list[RetrieveResponseEntitiesItem]):
        relationships (list[RetrieveResponseRelationshipsItem]):
        context_summary (str):
        retrieval_method (str):
    """

    query: str
    entities: list[RetrieveResponseEntitiesItem]
    relationships: list[RetrieveResponseRelationshipsItem]
    context_summary: str
    retrieval_method: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        entities = []
        for entities_item_data in self.entities:
            entities_item = entities_item_data.to_dict()
            entities.append(entities_item)

        relationships = []
        for relationships_item_data in self.relationships:
            relationships_item = relationships_item_data.to_dict()
            relationships.append(relationships_item)

        context_summary = self.context_summary

        retrieval_method = self.retrieval_method

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
                "entities": entities,
                "relationships": relationships,
                "context_summary": context_summary,
                "retrieval_method": retrieval_method,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.retrieve_response_entities_item import RetrieveResponseEntitiesItem
        from ..models.retrieve_response_relationships_item import RetrieveResponseRelationshipsItem

        d = dict(src_dict)
        query = d.pop("query")

        entities = []
        _entities = d.pop("entities")
        for entities_item_data in _entities:
            entities_item = RetrieveResponseEntitiesItem.from_dict(entities_item_data)

            entities.append(entities_item)

        relationships = []
        _relationships = d.pop("relationships")
        for relationships_item_data in _relationships:
            relationships_item = RetrieveResponseRelationshipsItem.from_dict(relationships_item_data)

            relationships.append(relationships_item)

        context_summary = d.pop("context_summary")

        retrieval_method = d.pop("retrieval_method")

        retrieve_response = cls(
            query=query,
            entities=entities,
            relationships=relationships,
            context_summary=context_summary,
            retrieval_method=retrieval_method,
        )

        retrieve_response.additional_properties = d
        return retrieve_response

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
