from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_simulation_request_target_profile import CreateSimulationRequestTargetProfile


T = TypeVar("T", bound="CreateSimulationRequest")


@_attrs_define
class CreateSimulationRequest:
    """
    Attributes:
        name (str): Human-readable simulation name
        target_profile (CreateSimulationRequestTargetProfile | Unset): Optional metadata about target scope
        tactics (list[str] | Unset): MITRE ATT&CK tactics to include. Empty = all. Valid: ['initial_access',
            'execution', 'persistence', 'privilege_escalation', 'lateral_movement', 'collection', 'exfiltration',
            'command_and_control']
        intensity (str | Unset): Simulation intensity: ['low', 'medium', 'high'] Default: 'medium'.
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    name: str
    target_profile: CreateSimulationRequestTargetProfile | Unset = UNSET
    tactics: list[str] | Unset = UNSET
    intensity: str | Unset = "medium"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        target_profile: dict[str, Any] | Unset = UNSET
        if not isinstance(self.target_profile, Unset):
            target_profile = self.target_profile.to_dict()

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        intensity = self.intensity

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if target_profile is not UNSET:
            field_dict["target_profile"] = target_profile
        if tactics is not UNSET:
            field_dict["tactics"] = tactics
        if intensity is not UNSET:
            field_dict["intensity"] = intensity
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_simulation_request_target_profile import CreateSimulationRequestTargetProfile

        d = dict(src_dict)
        name = d.pop("name")

        _target_profile = d.pop("target_profile", UNSET)
        target_profile: CreateSimulationRequestTargetProfile | Unset
        if isinstance(_target_profile, Unset):
            target_profile = UNSET
        else:
            target_profile = CreateSimulationRequestTargetProfile.from_dict(_target_profile)

        tactics = cast(list[str], d.pop("tactics", UNSET))

        intensity = d.pop("intensity", UNSET)

        org_id = d.pop("org_id", UNSET)

        create_simulation_request = cls(
            name=name,
            target_profile=target_profile,
            tactics=tactics,
            intensity=intensity,
            org_id=org_id,
        )

        create_simulation_request.additional_properties = d
        return create_simulation_request

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
