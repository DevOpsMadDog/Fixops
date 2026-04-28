from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cloud_graph_stats import CloudGraphStats
    from ..models.graph_edge import GraphEdge
    from ..models.graph_node import GraphNode


T = TypeVar("T", bound="CloudGraph")


@_attrs_define
class CloudGraph:
    """
    Attributes:
        nodes (list[GraphNode] | Unset):
        edges (list[GraphEdge] | Unset):
        stats (CloudGraphStats | Unset):
    """

    nodes: list[GraphNode] | Unset = UNSET
    edges: list[GraphEdge] | Unset = UNSET
    stats: CloudGraphStats | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        nodes: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.nodes, Unset):
            nodes = []
            for nodes_item_data in self.nodes:
                nodes_item = nodes_item_data.to_dict()
                nodes.append(nodes_item)

        edges: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.edges, Unset):
            edges = []
            for edges_item_data in self.edges:
                edges_item = edges_item_data.to_dict()
                edges.append(edges_item)

        stats: dict[str, Any] | Unset = UNSET
        if not isinstance(self.stats, Unset):
            stats = self.stats.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if nodes is not UNSET:
            field_dict["nodes"] = nodes
        if edges is not UNSET:
            field_dict["edges"] = edges
        if stats is not UNSET:
            field_dict["stats"] = stats

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cloud_graph_stats import CloudGraphStats
        from ..models.graph_edge import GraphEdge
        from ..models.graph_node import GraphNode

        d = dict(src_dict)
        _nodes = d.pop("nodes", UNSET)
        nodes: list[GraphNode] | Unset = UNSET
        if _nodes is not UNSET:
            nodes = []
            for nodes_item_data in _nodes:
                nodes_item = GraphNode.from_dict(nodes_item_data)

                nodes.append(nodes_item)

        _edges = d.pop("edges", UNSET)
        edges: list[GraphEdge] | Unset = UNSET
        if _edges is not UNSET:
            edges = []
            for edges_item_data in _edges:
                edges_item = GraphEdge.from_dict(edges_item_data)

                edges.append(edges_item)

        _stats = d.pop("stats", UNSET)
        stats: CloudGraphStats | Unset
        if isinstance(_stats, Unset):
            stats = UNSET
        else:
            stats = CloudGraphStats.from_dict(_stats)

        cloud_graph = cls(
            nodes=nodes,
            edges=edges,
            stats=stats,
        )

        cloud_graph.additional_properties = d
        return cloud_graph

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
