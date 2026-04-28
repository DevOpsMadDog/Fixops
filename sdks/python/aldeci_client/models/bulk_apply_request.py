from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.entity_type import EntityType

T = TypeVar("T", bound="BulkApplyRequest")


@_attrs_define
class BulkApplyRequest:
    """
    Attributes:
        entity_type (EntityType):
        entity_ids (list[str]): List of entity IDs
        tag_ids (list[str]): List of tag IDs to apply
    """

    entity_type: EntityType
    entity_ids: list[str]
    tag_ids: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_type = self.entity_type.value

        entity_ids = self.entity_ids

        tag_ids = self.tag_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_type": entity_type,
                "entity_ids": entity_ids,
                "tag_ids": tag_ids,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entity_type = EntityType(d.pop("entity_type"))

        entity_ids = cast(list[str], d.pop("entity_ids"))

        tag_ids = cast(list[str], d.pop("tag_ids"))

        bulk_apply_request = cls(
            entity_type=entity_type,
            entity_ids=entity_ids,
            tag_ids=tag_ids,
        )

        bulk_apply_request.additional_properties = d
        return bulk_apply_request

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
