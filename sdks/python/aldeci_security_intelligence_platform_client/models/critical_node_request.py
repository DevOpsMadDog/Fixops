from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.connection import Connection
    from ..models.infrastructure_node import InfrastructureNode


T = TypeVar("T", bound="CriticalNodeRequest")


@_attrs_define
class CriticalNodeRequest:
    """Request for critical node identification.

    Attributes:
        infrastructure (list[InfrastructureNode]):
        connections (list[Connection]):
        top_k (int | Unset):  Default: 10.
    """

    infrastructure: list[InfrastructureNode]
    connections: list[Connection]
    top_k: int | Unset = 10
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        infrastructure = []
        for infrastructure_item_data in self.infrastructure:
            infrastructure_item = infrastructure_item_data.to_dict()
            infrastructure.append(infrastructure_item)

        connections = []
        for connections_item_data in self.connections:
            connections_item = connections_item_data.to_dict()
            connections.append(connections_item)

        top_k = self.top_k

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "infrastructure": infrastructure,
                "connections": connections,
            }
        )
        if top_k is not UNSET:
            field_dict["top_k"] = top_k

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.connection import Connection
        from ..models.infrastructure_node import InfrastructureNode

        d = dict(src_dict)
        infrastructure = []
        _infrastructure = d.pop("infrastructure")
        for infrastructure_item_data in _infrastructure:
            infrastructure_item = InfrastructureNode.from_dict(infrastructure_item_data)

            infrastructure.append(infrastructure_item)

        connections = []
        _connections = d.pop("connections")
        for connections_item_data in _connections:
            connections_item = Connection.from_dict(connections_item_data)

            connections.append(connections_item)

        top_k = d.pop("top_k", UNSET)

        critical_node_request = cls(
            infrastructure=infrastructure,
            connections=connections,
            top_k=top_k,
        )

        critical_node_request.additional_properties = d
        return critical_node_request

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
