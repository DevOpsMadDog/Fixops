from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.field_mapping_update_mappings_item import FieldMappingUpdateMappingsItem


T = TypeVar("T", bound="FieldMappingUpdate")


@_attrs_define
class FieldMappingUpdate:
    """
    Attributes:
        connection_id (str):
        mappings (list[FieldMappingUpdateMappingsItem]): List of {aldeci_field, snow_field, transform}
        sync_type (str | Unset):  Default: 'cmdb'.
    """

    connection_id: str
    mappings: list[FieldMappingUpdateMappingsItem]
    sync_type: str | Unset = "cmdb"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        connection_id = self.connection_id

        mappings = []
        for mappings_item_data in self.mappings:
            mappings_item = mappings_item_data.to_dict()
            mappings.append(mappings_item)

        sync_type = self.sync_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "connection_id": connection_id,
                "mappings": mappings,
            }
        )
        if sync_type is not UNSET:
            field_dict["sync_type"] = sync_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.field_mapping_update_mappings_item import FieldMappingUpdateMappingsItem

        d = dict(src_dict)
        connection_id = d.pop("connection_id")

        mappings = []
        _mappings = d.pop("mappings")
        for mappings_item_data in _mappings:
            mappings_item = FieldMappingUpdateMappingsItem.from_dict(mappings_item_data)

            mappings.append(mappings_item)

        sync_type = d.pop("sync_type", UNSET)

        field_mapping_update = cls(
            connection_id=connection_id,
            mappings=mappings,
            sync_type=sync_type,
        )

        field_mapping_update.additional_properties = d
        return field_mapping_update

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
