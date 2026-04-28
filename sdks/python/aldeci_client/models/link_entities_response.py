from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="LinkEntitiesResponse")


@_attrs_define
class LinkEntitiesResponse:
    """Response after creating a relationship.

    Attributes:
        rel_id (str):
        entity_a_id (str):
        entity_b_id (str):
        relationship_type (str):
        status (str):
    """

    rel_id: str
    entity_a_id: str
    entity_b_id: str
    relationship_type: str
    status: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rel_id = self.rel_id

        entity_a_id = self.entity_a_id

        entity_b_id = self.entity_b_id

        relationship_type = self.relationship_type

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rel_id": rel_id,
                "entity_a_id": entity_a_id,
                "entity_b_id": entity_b_id,
                "relationship_type": relationship_type,
                "status": status,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rel_id = d.pop("rel_id")

        entity_a_id = d.pop("entity_a_id")

        entity_b_id = d.pop("entity_b_id")

        relationship_type = d.pop("relationship_type")

        status = d.pop("status")

        link_entities_response = cls(
            rel_id=rel_id,
            entity_a_id=entity_a_id,
            entity_b_id=entity_b_id,
            relationship_type=relationship_type,
            status=status,
        )

        link_entities_response.additional_properties = d
        return link_entities_response

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
