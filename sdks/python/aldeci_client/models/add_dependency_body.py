from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddDependencyBody")


@_attrs_define
class AddDependencyBody:
    """
    Attributes:
        source_service_id (str): Service ID that has the dependency
        target_service_id (str): Service ID being depended upon
        dependency_type (str | Unset): runtime | build | test | optional | fallback Default: 'runtime'.
        criticality (str | Unset): critical | high | medium | low Default: 'medium'.
        protocol (str | Unset): Network protocol (e.g. HTTPS, gRPC) Default: ''.
        port (int | Unset): Port number (0 = not applicable) Default: 0.
        description (str | Unset): Human-readable description Default: ''.
    """

    source_service_id: str
    target_service_id: str
    dependency_type: str | Unset = "runtime"
    criticality: str | Unset = "medium"
    protocol: str | Unset = ""
    port: int | Unset = 0
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_service_id = self.source_service_id

        target_service_id = self.target_service_id

        dependency_type = self.dependency_type

        criticality = self.criticality

        protocol = self.protocol

        port = self.port

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_service_id": source_service_id,
                "target_service_id": target_service_id,
            }
        )
        if dependency_type is not UNSET:
            field_dict["dependency_type"] = dependency_type
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if port is not UNSET:
            field_dict["port"] = port
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_service_id = d.pop("source_service_id")

        target_service_id = d.pop("target_service_id")

        dependency_type = d.pop("dependency_type", UNSET)

        criticality = d.pop("criticality", UNSET)

        protocol = d.pop("protocol", UNSET)

        port = d.pop("port", UNSET)

        description = d.pop("description", UNSET)

        add_dependency_body = cls(
            source_service_id=source_service_id,
            target_service_id=target_service_id,
            dependency_type=dependency_type,
            criticality=criticality,
            protocol=protocol,
            port=port,
            description=description,
        )

        add_dependency_body.additional_properties = d
        return add_dependency_body

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
