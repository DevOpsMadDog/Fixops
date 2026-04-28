from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.edge_type import EdgeType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.graph_edge_metadata import GraphEdgeMetadata


T = TypeVar("T", bound="GraphEdge")


@_attrs_define
class GraphEdge:
    """
    Attributes:
        source_id (str):
        target_id (str):
        type_ (EdgeType):
        id (str | Unset):
        metadata (GraphEdgeMetadata | Unset):
    """

    source_id: str
    target_id: str
    type_: EdgeType
    id: str | Unset = UNSET
    metadata: GraphEdgeMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_id = self.source_id

        target_id = self.target_id

        type_ = self.type_.value

        id = self.id

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_id": source_id,
                "target_id": target_id,
                "type": type_,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.graph_edge_metadata import GraphEdgeMetadata

        d = dict(src_dict)
        source_id = d.pop("source_id")

        target_id = d.pop("target_id")

        type_ = EdgeType(d.pop("type"))

        id = d.pop("id", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: GraphEdgeMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = GraphEdgeMetadata.from_dict(_metadata)

        graph_edge = cls(
            source_id=source_id,
            target_id=target_id,
            type_=type_,
            id=id,
            metadata=metadata,
        )

        graph_edge.additional_properties = d
        return graph_edge

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
