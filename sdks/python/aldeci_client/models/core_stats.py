from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.core_stats_entity_types import CoreStatsEntityTypes


T = TypeVar("T", bound="CoreStats")


@_attrs_define
class CoreStats:
    """Core statistics.

    Attributes:
        entity_count (int):
        relationship_count (int):
        last_updated (None | str):
        entity_types (CoreStatsEntityTypes):
    """

    entity_count: int
    relationship_count: int
    last_updated: None | str
    entity_types: CoreStatsEntityTypes
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_count = self.entity_count

        relationship_count = self.relationship_count

        last_updated: None | str
        last_updated = self.last_updated

        entity_types = self.entity_types.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_count": entity_count,
                "relationship_count": relationship_count,
                "last_updated": last_updated,
                "entity_types": entity_types,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.core_stats_entity_types import CoreStatsEntityTypes

        d = dict(src_dict)
        entity_count = d.pop("entity_count")

        relationship_count = d.pop("relationship_count")

        def _parse_last_updated(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        last_updated = _parse_last_updated(d.pop("last_updated"))

        entity_types = CoreStatsEntityTypes.from_dict(d.pop("entity_types"))

        core_stats = cls(
            entity_count=entity_count,
            relationship_count=relationship_count,
            last_updated=last_updated,
            entity_types=entity_types,
        )

        core_stats.additional_properties = d
        return core_stats

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
