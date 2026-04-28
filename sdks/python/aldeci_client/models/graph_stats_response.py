from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.graph_stats_response_entities_per_core import GraphStatsResponseEntitiesPerCore
    from ..models.graph_stats_response_relationships_per_core import GraphStatsResponseRelationshipsPerCore


T = TypeVar("T", bound="GraphStatsResponse")


@_attrs_define
class GraphStatsResponse:
    """High-level graph statistics.

    Attributes:
        total_entities (int):
        total_relationships (int):
        entities_per_core (GraphStatsResponseEntitiesPerCore):
        relationships_per_core (GraphStatsResponseRelationshipsPerCore):
        coverage_pct (float):
        orphaned_count (int):
        last_updated (None | str):
        db_path (str):
    """

    total_entities: int
    total_relationships: int
    entities_per_core: GraphStatsResponseEntitiesPerCore
    relationships_per_core: GraphStatsResponseRelationshipsPerCore
    coverage_pct: float
    orphaned_count: int
    last_updated: None | str
    db_path: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_entities = self.total_entities

        total_relationships = self.total_relationships

        entities_per_core = self.entities_per_core.to_dict()

        relationships_per_core = self.relationships_per_core.to_dict()

        coverage_pct = self.coverage_pct

        orphaned_count = self.orphaned_count

        last_updated: None | str
        last_updated = self.last_updated

        db_path = self.db_path

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_entities": total_entities,
                "total_relationships": total_relationships,
                "entities_per_core": entities_per_core,
                "relationships_per_core": relationships_per_core,
                "coverage_pct": coverage_pct,
                "orphaned_count": orphaned_count,
                "last_updated": last_updated,
                "db_path": db_path,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.graph_stats_response_entities_per_core import GraphStatsResponseEntitiesPerCore
        from ..models.graph_stats_response_relationships_per_core import GraphStatsResponseRelationshipsPerCore

        d = dict(src_dict)
        total_entities = d.pop("total_entities")

        total_relationships = d.pop("total_relationships")

        entities_per_core = GraphStatsResponseEntitiesPerCore.from_dict(d.pop("entities_per_core"))

        relationships_per_core = GraphStatsResponseRelationshipsPerCore.from_dict(d.pop("relationships_per_core"))

        coverage_pct = d.pop("coverage_pct")

        orphaned_count = d.pop("orphaned_count")

        def _parse_last_updated(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        last_updated = _parse_last_updated(d.pop("last_updated"))

        db_path = d.pop("db_path")

        graph_stats_response = cls(
            total_entities=total_entities,
            total_relationships=total_relationships,
            entities_per_core=entities_per_core,
            relationships_per_core=relationships_per_core,
            coverage_pct=coverage_pct,
            orphaned_count=orphaned_count,
            last_updated=last_updated,
            db_path=db_path,
        )

        graph_stats_response.additional_properties = d
        return graph_stats_response

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
