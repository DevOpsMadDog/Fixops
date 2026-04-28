from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.attack_surface_snapshot_metadata import AttackSurfaceSnapshotMetadata
    from ..models.service_info import ServiceInfo


T = TypeVar("T", bound="AttackSurfaceSnapshot")


@_attrs_define
class AttackSurfaceSnapshot:
    """
    Attributes:
        target (str):
        id (str | Unset):
        timestamp (str | Unset):
        open_ports (list[int] | Unset):
        services (list[ServiceInfo] | Unset):
        endpoints (list[str] | Unset):
        deps (list[str] | Unset):
        secrets_exposed (list[str] | Unset):
        score (float | Unset):  Default: 0.0.
        metadata (AttackSurfaceSnapshotMetadata | Unset):
    """

    target: str
    id: str | Unset = UNSET
    timestamp: str | Unset = UNSET
    open_ports: list[int] | Unset = UNSET
    services: list[ServiceInfo] | Unset = UNSET
    endpoints: list[str] | Unset = UNSET
    deps: list[str] | Unset = UNSET
    secrets_exposed: list[str] | Unset = UNSET
    score: float | Unset = 0.0
    metadata: AttackSurfaceSnapshotMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target = self.target

        id = self.id

        timestamp = self.timestamp

        open_ports: list[int] | Unset = UNSET
        if not isinstance(self.open_ports, Unset):
            open_ports = self.open_ports

        services: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.services, Unset):
            services = []
            for services_item_data in self.services:
                services_item = services_item_data.to_dict()
                services.append(services_item)

        endpoints: list[str] | Unset = UNSET
        if not isinstance(self.endpoints, Unset):
            endpoints = self.endpoints

        deps: list[str] | Unset = UNSET
        if not isinstance(self.deps, Unset):
            deps = self.deps

        secrets_exposed: list[str] | Unset = UNSET
        if not isinstance(self.secrets_exposed, Unset):
            secrets_exposed = self.secrets_exposed

        score = self.score

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target": target,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp
        if open_ports is not UNSET:
            field_dict["open_ports"] = open_ports
        if services is not UNSET:
            field_dict["services"] = services
        if endpoints is not UNSET:
            field_dict["endpoints"] = endpoints
        if deps is not UNSET:
            field_dict["deps"] = deps
        if secrets_exposed is not UNSET:
            field_dict["secrets_exposed"] = secrets_exposed
        if score is not UNSET:
            field_dict["score"] = score
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.attack_surface_snapshot_metadata import AttackSurfaceSnapshotMetadata
        from ..models.service_info import ServiceInfo

        d = dict(src_dict)
        target = d.pop("target")

        id = d.pop("id", UNSET)

        timestamp = d.pop("timestamp", UNSET)

        open_ports = cast(list[int], d.pop("open_ports", UNSET))

        _services = d.pop("services", UNSET)
        services: list[ServiceInfo] | Unset = UNSET
        if _services is not UNSET:
            services = []
            for services_item_data in _services:
                services_item = ServiceInfo.from_dict(services_item_data)

                services.append(services_item)

        endpoints = cast(list[str], d.pop("endpoints", UNSET))

        deps = cast(list[str], d.pop("deps", UNSET))

        secrets_exposed = cast(list[str], d.pop("secrets_exposed", UNSET))

        score = d.pop("score", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: AttackSurfaceSnapshotMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AttackSurfaceSnapshotMetadata.from_dict(_metadata)

        attack_surface_snapshot = cls(
            target=target,
            id=id,
            timestamp=timestamp,
            open_ports=open_ports,
            services=services,
            endpoints=endpoints,
            deps=deps,
            secrets_exposed=secrets_exposed,
            score=score,
            metadata=metadata,
        )

        attack_surface_snapshot.additional_properties = d
        return attack_surface_snapshot

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
