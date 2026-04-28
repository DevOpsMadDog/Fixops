from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.core_stats import CoreStats


T = TypeVar("T", bound="CoreResponse")


@_attrs_define
class CoreResponse:
    """Knowledge Core information.

    Attributes:
        core_id (int):
        name (str):
        description (str):
        entity_types (list[str]):
        stats (CoreStats): Core statistics.
    """

    core_id: int
    name: str
    description: str
    entity_types: list[str]
    stats: CoreStats
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        core_id = self.core_id

        name = self.name

        description = self.description

        entity_types = self.entity_types

        stats = self.stats.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "core_id": core_id,
                "name": name,
                "description": description,
                "entity_types": entity_types,
                "stats": stats,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.core_stats import CoreStats

        d = dict(src_dict)
        core_id = d.pop("core_id")

        name = d.pop("name")

        description = d.pop("description")

        entity_types = cast(list[str], d.pop("entity_types"))

        stats = CoreStats.from_dict(d.pop("stats"))

        core_response = cls(
            core_id=core_id,
            name=name,
            description=description,
            entity_types=entity_types,
            stats=stats,
        )

        core_response.additional_properties = d
        return core_response

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
