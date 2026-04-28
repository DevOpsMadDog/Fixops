from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.link_entities_request_properties_type_0 import LinkEntitiesRequestPropertiesType0


T = TypeVar("T", bound="LinkEntitiesRequest")


@_attrs_define
class LinkEntitiesRequest:
    """Create a typed relationship between two entities.

    Attributes:
        entity_a_id (str): Source entity ID
        entity_b_id (str): Target entity ID
        relationship_type (str): Relationship type (see RelationshipType constants)
        confidence (float | Unset): Edge confidence score Default: 0.95.
        properties (LinkEntitiesRequestPropertiesType0 | None | Unset): Optional edge properties
        org_id (None | str | Unset): Tenant org ID Default: 'default'.
    """

    entity_a_id: str
    entity_b_id: str
    relationship_type: str
    confidence: float | Unset = 0.95
    properties: LinkEntitiesRequestPropertiesType0 | None | Unset = UNSET
    org_id: None | str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.link_entities_request_properties_type_0 import LinkEntitiesRequestPropertiesType0

        entity_a_id = self.entity_a_id

        entity_b_id = self.entity_b_id

        relationship_type = self.relationship_type

        confidence = self.confidence

        properties: dict[str, Any] | None | Unset
        if isinstance(self.properties, Unset):
            properties = UNSET
        elif isinstance(self.properties, LinkEntitiesRequestPropertiesType0):
            properties = self.properties.to_dict()
        else:
            properties = self.properties

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_a_id": entity_a_id,
                "entity_b_id": entity_b_id,
                "relationship_type": relationship_type,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if properties is not UNSET:
            field_dict["properties"] = properties
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.link_entities_request_properties_type_0 import LinkEntitiesRequestPropertiesType0

        d = dict(src_dict)
        entity_a_id = d.pop("entity_a_id")

        entity_b_id = d.pop("entity_b_id")

        relationship_type = d.pop("relationship_type")

        confidence = d.pop("confidence", UNSET)

        def _parse_properties(data: object) -> LinkEntitiesRequestPropertiesType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                properties_type_0 = LinkEntitiesRequestPropertiesType0.from_dict(data)

                return properties_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(LinkEntitiesRequestPropertiesType0 | None | Unset, data)

        properties = _parse_properties(d.pop("properties", UNSET))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        link_entities_request = cls(
            entity_a_id=entity_a_id,
            entity_b_id=entity_b_id,
            relationship_type=relationship_type,
            confidence=confidence,
            properties=properties,
            org_id=org_id,
        )

        link_entities_request.additional_properties = d
        return link_entities_request

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
