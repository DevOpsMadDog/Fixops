from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.core_coverage_response_entity_type_breakdown import CoreCoverageResponseEntityTypeBreakdown


T = TypeVar("T", bound="CoreCoverageResponse")


@_attrs_define
class CoreCoverageResponse:
    """Coverage stats for one Knowledge Core.

    Attributes:
        core_id (int):
        core_name (str):
        total_entities (int):
        connected_entities (int):
        orphaned_entities (int):
        coverage_pct (float):
        entity_type_breakdown (CoreCoverageResponseEntityTypeBreakdown):
        last_updated (None | str):
    """

    core_id: int
    core_name: str
    total_entities: int
    connected_entities: int
    orphaned_entities: int
    coverage_pct: float
    entity_type_breakdown: CoreCoverageResponseEntityTypeBreakdown
    last_updated: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        core_id = self.core_id

        core_name = self.core_name

        total_entities = self.total_entities

        connected_entities = self.connected_entities

        orphaned_entities = self.orphaned_entities

        coverage_pct = self.coverage_pct

        entity_type_breakdown = self.entity_type_breakdown.to_dict()

        last_updated: None | str
        last_updated = self.last_updated

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "core_id": core_id,
                "core_name": core_name,
                "total_entities": total_entities,
                "connected_entities": connected_entities,
                "orphaned_entities": orphaned_entities,
                "coverage_pct": coverage_pct,
                "entity_type_breakdown": entity_type_breakdown,
                "last_updated": last_updated,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.core_coverage_response_entity_type_breakdown import CoreCoverageResponseEntityTypeBreakdown

        d = dict(src_dict)
        core_id = d.pop("core_id")

        core_name = d.pop("core_name")

        total_entities = d.pop("total_entities")

        connected_entities = d.pop("connected_entities")

        orphaned_entities = d.pop("orphaned_entities")

        coverage_pct = d.pop("coverage_pct")

        entity_type_breakdown = CoreCoverageResponseEntityTypeBreakdown.from_dict(d.pop("entity_type_breakdown"))

        def _parse_last_updated(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        last_updated = _parse_last_updated(d.pop("last_updated"))

        core_coverage_response = cls(
            core_id=core_id,
            core_name=core_name,
            total_entities=total_entities,
            connected_entities=connected_entities,
            orphaned_entities=orphaned_entities,
            coverage_pct=coverage_pct,
            entity_type_breakdown=entity_type_breakdown,
            last_updated=last_updated,
        )

        core_coverage_response.additional_properties = d
        return core_coverage_response

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
