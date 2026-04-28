from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.service_info import ServiceInfo


T = TypeVar("T", bound="AttackSurfaceDiff")


@_attrs_define
class AttackSurfaceDiff:
    """
    Attributes:
        snapshot_old_id (str):
        snapshot_new_id (str):
        target (str):
        id (str | Unset):
        computed_at (str | Unset):
        added_ports (list[int] | Unset):
        removed_ports (list[int] | Unset):
        added_services (list[ServiceInfo] | Unset):
        removed_services (list[ServiceInfo] | Unset):
        added_endpoints (list[str] | Unset):
        removed_endpoints (list[str] | Unset):
        new_secrets (list[str] | Unset):
        closed_secrets (list[str] | Unset):
        score_delta (float | Unset):  Default: 0.0.
        risk_increased (bool | Unset):  Default: False.
        change_count (int | Unset):  Default: 0.
    """

    snapshot_old_id: str
    snapshot_new_id: str
    target: str
    id: str | Unset = UNSET
    computed_at: str | Unset = UNSET
    added_ports: list[int] | Unset = UNSET
    removed_ports: list[int] | Unset = UNSET
    added_services: list[ServiceInfo] | Unset = UNSET
    removed_services: list[ServiceInfo] | Unset = UNSET
    added_endpoints: list[str] | Unset = UNSET
    removed_endpoints: list[str] | Unset = UNSET
    new_secrets: list[str] | Unset = UNSET
    closed_secrets: list[str] | Unset = UNSET
    score_delta: float | Unset = 0.0
    risk_increased: bool | Unset = False
    change_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        snapshot_old_id = self.snapshot_old_id

        snapshot_new_id = self.snapshot_new_id

        target = self.target

        id = self.id

        computed_at = self.computed_at

        added_ports: list[int] | Unset = UNSET
        if not isinstance(self.added_ports, Unset):
            added_ports = self.added_ports

        removed_ports: list[int] | Unset = UNSET
        if not isinstance(self.removed_ports, Unset):
            removed_ports = self.removed_ports

        added_services: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.added_services, Unset):
            added_services = []
            for added_services_item_data in self.added_services:
                added_services_item = added_services_item_data.to_dict()
                added_services.append(added_services_item)

        removed_services: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.removed_services, Unset):
            removed_services = []
            for removed_services_item_data in self.removed_services:
                removed_services_item = removed_services_item_data.to_dict()
                removed_services.append(removed_services_item)

        added_endpoints: list[str] | Unset = UNSET
        if not isinstance(self.added_endpoints, Unset):
            added_endpoints = self.added_endpoints

        removed_endpoints: list[str] | Unset = UNSET
        if not isinstance(self.removed_endpoints, Unset):
            removed_endpoints = self.removed_endpoints

        new_secrets: list[str] | Unset = UNSET
        if not isinstance(self.new_secrets, Unset):
            new_secrets = self.new_secrets

        closed_secrets: list[str] | Unset = UNSET
        if not isinstance(self.closed_secrets, Unset):
            closed_secrets = self.closed_secrets

        score_delta = self.score_delta

        risk_increased = self.risk_increased

        change_count = self.change_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "snapshot_old_id": snapshot_old_id,
                "snapshot_new_id": snapshot_new_id,
                "target": target,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at
        if added_ports is not UNSET:
            field_dict["added_ports"] = added_ports
        if removed_ports is not UNSET:
            field_dict["removed_ports"] = removed_ports
        if added_services is not UNSET:
            field_dict["added_services"] = added_services
        if removed_services is not UNSET:
            field_dict["removed_services"] = removed_services
        if added_endpoints is not UNSET:
            field_dict["added_endpoints"] = added_endpoints
        if removed_endpoints is not UNSET:
            field_dict["removed_endpoints"] = removed_endpoints
        if new_secrets is not UNSET:
            field_dict["new_secrets"] = new_secrets
        if closed_secrets is not UNSET:
            field_dict["closed_secrets"] = closed_secrets
        if score_delta is not UNSET:
            field_dict["score_delta"] = score_delta
        if risk_increased is not UNSET:
            field_dict["risk_increased"] = risk_increased
        if change_count is not UNSET:
            field_dict["change_count"] = change_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.service_info import ServiceInfo

        d = dict(src_dict)
        snapshot_old_id = d.pop("snapshot_old_id")

        snapshot_new_id = d.pop("snapshot_new_id")

        target = d.pop("target")

        id = d.pop("id", UNSET)

        computed_at = d.pop("computed_at", UNSET)

        added_ports = cast(list[int], d.pop("added_ports", UNSET))

        removed_ports = cast(list[int], d.pop("removed_ports", UNSET))

        _added_services = d.pop("added_services", UNSET)
        added_services: list[ServiceInfo] | Unset = UNSET
        if _added_services is not UNSET:
            added_services = []
            for added_services_item_data in _added_services:
                added_services_item = ServiceInfo.from_dict(added_services_item_data)

                added_services.append(added_services_item)

        _removed_services = d.pop("removed_services", UNSET)
        removed_services: list[ServiceInfo] | Unset = UNSET
        if _removed_services is not UNSET:
            removed_services = []
            for removed_services_item_data in _removed_services:
                removed_services_item = ServiceInfo.from_dict(removed_services_item_data)

                removed_services.append(removed_services_item)

        added_endpoints = cast(list[str], d.pop("added_endpoints", UNSET))

        removed_endpoints = cast(list[str], d.pop("removed_endpoints", UNSET))

        new_secrets = cast(list[str], d.pop("new_secrets", UNSET))

        closed_secrets = cast(list[str], d.pop("closed_secrets", UNSET))

        score_delta = d.pop("score_delta", UNSET)

        risk_increased = d.pop("risk_increased", UNSET)

        change_count = d.pop("change_count", UNSET)

        attack_surface_diff = cls(
            snapshot_old_id=snapshot_old_id,
            snapshot_new_id=snapshot_new_id,
            target=target,
            id=id,
            computed_at=computed_at,
            added_ports=added_ports,
            removed_ports=removed_ports,
            added_services=added_services,
            removed_services=removed_services,
            added_endpoints=added_endpoints,
            removed_endpoints=removed_endpoints,
            new_secrets=new_secrets,
            closed_secrets=closed_secrets,
            score_delta=score_delta,
            risk_increased=risk_increased,
            change_count=change_count,
        )

        attack_surface_diff.additional_properties = d
        return attack_surface_diff

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
