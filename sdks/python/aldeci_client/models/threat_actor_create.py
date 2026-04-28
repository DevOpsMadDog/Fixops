from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatActorCreate")


@_attrs_define
class ThreatActorCreate:
    """
    Attributes:
        actor_name (str): Actor name
        actor_type (str | Unset): nation_state/criminal/insider/hacktivist/competitor/researcher Default: 'criminal'.
        motivation (str | Unset): Motivation Default: ''.
        capability (str | Unset): sophisticated/moderate/basic Default: 'moderate'.
        target_assets (list[str] | Unset): Targeted assets
        tactics (list[str] | Unset): TTPs/tactics
    """

    actor_name: str
    actor_type: str | Unset = "criminal"
    motivation: str | Unset = ""
    capability: str | Unset = "moderate"
    target_assets: list[str] | Unset = UNSET
    tactics: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        actor_name = self.actor_name

        actor_type = self.actor_type

        motivation = self.motivation

        capability = self.capability

        target_assets: list[str] | Unset = UNSET
        if not isinstance(self.target_assets, Unset):
            target_assets = self.target_assets

        tactics: list[str] | Unset = UNSET
        if not isinstance(self.tactics, Unset):
            tactics = self.tactics

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "actor_name": actor_name,
            }
        )
        if actor_type is not UNSET:
            field_dict["actor_type"] = actor_type
        if motivation is not UNSET:
            field_dict["motivation"] = motivation
        if capability is not UNSET:
            field_dict["capability"] = capability
        if target_assets is not UNSET:
            field_dict["target_assets"] = target_assets
        if tactics is not UNSET:
            field_dict["tactics"] = tactics

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        actor_name = d.pop("actor_name")

        actor_type = d.pop("actor_type", UNSET)

        motivation = d.pop("motivation", UNSET)

        capability = d.pop("capability", UNSET)

        target_assets = cast(list[str], d.pop("target_assets", UNSET))

        tactics = cast(list[str], d.pop("tactics", UNSET))

        threat_actor_create = cls(
            actor_name=actor_name,
            actor_type=actor_type,
            motivation=motivation,
            capability=capability,
            target_assets=target_assets,
            tactics=tactics,
        )

        threat_actor_create.additional_properties = d
        return threat_actor_create

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
