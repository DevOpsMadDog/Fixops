from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.entity_attributes_body_entity_attributes import EntityAttributesBodyEntityAttributes


T = TypeVar("T", bound="EntityAttributesBody")


@_attrs_define
class EntityAttributesBody:
    """Body for POST /simulate.

    Attributes:
        entity_attributes (EntityAttributesBodyEntityAttributes | Unset):
    """

    entity_attributes: EntityAttributesBodyEntityAttributes | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_attributes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.entity_attributes, Unset):
            entity_attributes = self.entity_attributes.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if entity_attributes is not UNSET:
            field_dict["entity_attributes"] = entity_attributes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.entity_attributes_body_entity_attributes import EntityAttributesBodyEntityAttributes

        d = dict(src_dict)
        _entity_attributes = d.pop("entity_attributes", UNSET)
        entity_attributes: EntityAttributesBodyEntityAttributes | Unset
        if isinstance(_entity_attributes, Unset):
            entity_attributes = UNSET
        else:
            entity_attributes = EntityAttributesBodyEntityAttributes.from_dict(_entity_attributes)

        entity_attributes_body = cls(
            entity_attributes=entity_attributes,
        )

        entity_attributes_body.additional_properties = d
        return entity_attributes_body

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
