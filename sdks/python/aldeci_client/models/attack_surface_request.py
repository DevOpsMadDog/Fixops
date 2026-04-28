from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.connection import Connection
    from ..models.infrastructure_node import InfrastructureNode
    from ..models.vulnerability_node import VulnerabilityNode


T = TypeVar("T", bound="AttackSurfaceRequest")


@_attrs_define
class AttackSurfaceRequest:
    """Request for attack surface analysis.

    Attributes:
        infrastructure (list[InfrastructureNode]): Infrastructure nodes
        connections (list[Connection] | Unset): Connections
        vulnerabilities (list[VulnerabilityNode] | Unset): Vulnerabilities
        max_paths (int | Unset): Maximum attack paths to return Default: 10.
    """

    infrastructure: list[InfrastructureNode]
    connections: list[Connection] | Unset = UNSET
    vulnerabilities: list[VulnerabilityNode] | Unset = UNSET
    max_paths: int | Unset = 10
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        infrastructure = []
        for infrastructure_item_data in self.infrastructure:
            infrastructure_item = infrastructure_item_data.to_dict()
            infrastructure.append(infrastructure_item)

        connections: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.connections, Unset):
            connections = []
            for connections_item_data in self.connections:
                connections_item = connections_item_data.to_dict()
                connections.append(connections_item)

        vulnerabilities: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.vulnerabilities, Unset):
            vulnerabilities = []
            for vulnerabilities_item_data in self.vulnerabilities:
                vulnerabilities_item = vulnerabilities_item_data.to_dict()
                vulnerabilities.append(vulnerabilities_item)

        max_paths = self.max_paths

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "infrastructure": infrastructure,
            }
        )
        if connections is not UNSET:
            field_dict["connections"] = connections
        if vulnerabilities is not UNSET:
            field_dict["vulnerabilities"] = vulnerabilities
        if max_paths is not UNSET:
            field_dict["max_paths"] = max_paths

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.connection import Connection
        from ..models.infrastructure_node import InfrastructureNode
        from ..models.vulnerability_node import VulnerabilityNode

        d = dict(src_dict)
        infrastructure = []
        _infrastructure = d.pop("infrastructure")
        for infrastructure_item_data in _infrastructure:
            infrastructure_item = InfrastructureNode.from_dict(infrastructure_item_data)

            infrastructure.append(infrastructure_item)

        _connections = d.pop("connections", UNSET)
        connections: list[Connection] | Unset = UNSET
        if _connections is not UNSET:
            connections = []
            for connections_item_data in _connections:
                connections_item = Connection.from_dict(connections_item_data)

                connections.append(connections_item)

        _vulnerabilities = d.pop("vulnerabilities", UNSET)
        vulnerabilities: list[VulnerabilityNode] | Unset = UNSET
        if _vulnerabilities is not UNSET:
            vulnerabilities = []
            for vulnerabilities_item_data in _vulnerabilities:
                vulnerabilities_item = VulnerabilityNode.from_dict(vulnerabilities_item_data)

                vulnerabilities.append(vulnerabilities_item)

        max_paths = d.pop("max_paths", UNSET)

        attack_surface_request = cls(
            infrastructure=infrastructure,
            connections=connections,
            vulnerabilities=vulnerabilities,
            max_paths=max_paths,
        )

        attack_surface_request.additional_properties = d
        return attack_surface_request

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
