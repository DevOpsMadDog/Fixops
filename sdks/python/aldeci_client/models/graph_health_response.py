from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.graph_health_response_cores import GraphHealthResponseCores


T = TypeVar("T", bound="GraphHealthResponse")


@_attrs_define
class GraphHealthResponse:
    """Response from /health.

    Attributes:
        status (str):
        graph_rag_available (bool):
        total_entities (int):
        total_relationships (int):
        cores (GraphHealthResponseCores):
    """

    status: str
    graph_rag_available: bool
    total_entities: int
    total_relationships: int
    cores: GraphHealthResponseCores
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        graph_rag_available = self.graph_rag_available

        total_entities = self.total_entities

        total_relationships = self.total_relationships

        cores = self.cores.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
                "graph_rag_available": graph_rag_available,
                "total_entities": total_entities,
                "total_relationships": total_relationships,
                "cores": cores,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.graph_health_response_cores import GraphHealthResponseCores

        d = dict(src_dict)
        status = d.pop("status")

        graph_rag_available = d.pop("graph_rag_available")

        total_entities = d.pop("total_entities")

        total_relationships = d.pop("total_relationships")

        cores = GraphHealthResponseCores.from_dict(d.pop("cores"))

        graph_health_response = cls(
            status=status,
            graph_rag_available=graph_rag_available,
            total_entities=total_entities,
            total_relationships=total_relationships,
            cores=cores,
        )

        graph_health_response.additional_properties = d
        return graph_health_response

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
