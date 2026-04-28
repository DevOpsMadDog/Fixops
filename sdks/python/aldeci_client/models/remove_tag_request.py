from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.entity_type import EntityType

T = TypeVar("T", bound="RemoveTagRequest")


@_attrs_define
class RemoveTagRequest:
    """
    Attributes:
        entity_type (EntityType):
        entity_id (str): Entity ID
        tag_id (str): Tag ID to remove
    """

    entity_type: EntityType
    entity_id: str
    tag_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_type = self.entity_type.value

        entity_id = self.entity_id

        tag_id = self.tag_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "tag_id": tag_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entity_type = EntityType(d.pop("entity_type"))

        entity_id = d.pop("entity_id")

        tag_id = d.pop("tag_id")

        remove_tag_request = cls(
            entity_type=entity_type,
            entity_id=entity_id,
            tag_id=tag_id,
        )

        remove_tag_request.additional_properties = d
        return remove_tag_request

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
