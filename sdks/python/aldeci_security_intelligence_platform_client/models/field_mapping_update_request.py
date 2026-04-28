from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.field_mapping_item import FieldMappingItem


T = TypeVar("T", bound="FieldMappingUpdateRequest")


@_attrs_define
class FieldMappingUpdateRequest:
    """
    Attributes:
        mappings (list[FieldMappingItem]): New field mapping list (replaces existing)
    """

    mappings: list[FieldMappingItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mappings = []
        for mappings_item_data in self.mappings:
            mappings_item = mappings_item_data.to_dict()
            mappings.append(mappings_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "mappings": mappings,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.field_mapping_item import FieldMappingItem

        d = dict(src_dict)
        mappings = []
        _mappings = d.pop("mappings")
        for mappings_item_data in _mappings:
            mappings_item = FieldMappingItem.from_dict(mappings_item_data)

            mappings.append(mappings_item)

        field_mapping_update_request = cls(
            mappings=mappings,
        )

        field_mapping_update_request.additional_properties = d
        return field_mapping_update_request

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
