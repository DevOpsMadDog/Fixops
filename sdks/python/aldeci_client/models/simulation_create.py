from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.simulation_create_target_profile import SimulationCreateTargetProfile


T = TypeVar("T", bound="SimulationCreate")


@_attrs_define
class SimulationCreate:
    """
    Attributes:
        name (str | Unset):  Default: 'Unnamed Simulation'.
        simulation_type (str | Unset): BAS | RedTeam | PenTest | Tabletop Default: 'BAS'.
        scope (str | Unset):  Default: ''.
        target_profile (SimulationCreateTargetProfile | Unset):
        status (str | Unset): planned | running | completed | failed | cancelled Default: 'planned'.
        started_at (None | str | Unset):
        completed_at (None | str | Unset):
    """

    name: str | Unset = "Unnamed Simulation"
    simulation_type: str | Unset = "BAS"
    scope: str | Unset = ""
    target_profile: SimulationCreateTargetProfile | Unset = UNSET
    status: str | Unset = "planned"
    started_at: None | str | Unset = UNSET
    completed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        simulation_type = self.simulation_type

        scope = self.scope

        target_profile: dict[str, Any] | Unset = UNSET
        if not isinstance(self.target_profile, Unset):
            target_profile = self.target_profile.to_dict()

        status = self.status

        started_at: None | str | Unset
        if isinstance(self.started_at, Unset):
            started_at = UNSET
        else:
            started_at = self.started_at

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if simulation_type is not UNSET:
            field_dict["simulation_type"] = simulation_type
        if scope is not UNSET:
            field_dict["scope"] = scope
        if target_profile is not UNSET:
            field_dict["target_profile"] = target_profile
        if status is not UNSET:
            field_dict["status"] = status
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.simulation_create_target_profile import SimulationCreateTargetProfile

        d = dict(src_dict)
        name = d.pop("name", UNSET)

        simulation_type = d.pop("simulation_type", UNSET)

        scope = d.pop("scope", UNSET)

        _target_profile = d.pop("target_profile", UNSET)
        target_profile: SimulationCreateTargetProfile | Unset
        if isinstance(_target_profile, Unset):
            target_profile = UNSET
        else:
            target_profile = SimulationCreateTargetProfile.from_dict(_target_profile)

        status = d.pop("status", UNSET)

        def _parse_started_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        started_at = _parse_started_at(d.pop("started_at", UNSET))

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        simulation_create = cls(
            name=name,
            simulation_type=simulation_type,
            scope=scope,
            target_profile=target_profile,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
        )

        simulation_create.additional_properties = d
        return simulation_create

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
