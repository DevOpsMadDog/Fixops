from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateActorRequest")


@_attrs_define
class CreateActorRequest:
    """
    Attributes:
        name (str): Threat actor name (required)
        org_id (str | Unset): Organisation identifier Default: 'default'.
        actor_type (str | Unset): Type: nation_state, criminal_group, hacktivist, insider, competitor, unknown Default:
            'unknown'.
        aliases (list[str] | Unset): Known aliases / alternate names
        origin_country (str | Unset): Country of origin (ISO-3166 code) Default: ''.
        motivation (str | Unset): Primary motivation (e.g. espionage, financial) Default: ''.
        sophistication (str | Unset): Sophistication level: advanced, moderate, basic Default: 'basic'.
        active (bool | Unset): Whether the actor is currently active Default: True.
    """

    name: str
    org_id: str | Unset = "default"
    actor_type: str | Unset = "unknown"
    aliases: list[str] | Unset = UNSET
    origin_country: str | Unset = ""
    motivation: str | Unset = ""
    sophistication: str | Unset = "basic"
    active: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_id = self.org_id

        actor_type = self.actor_type

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        origin_country = self.origin_country

        motivation = self.motivation

        sophistication = self.sophistication

        active = self.active

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if actor_type is not UNSET:
            field_dict["actor_type"] = actor_type
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if origin_country is not UNSET:
            field_dict["origin_country"] = origin_country
        if motivation is not UNSET:
            field_dict["motivation"] = motivation
        if sophistication is not UNSET:
            field_dict["sophistication"] = sophistication
        if active is not UNSET:
            field_dict["active"] = active

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        org_id = d.pop("org_id", UNSET)

        actor_type = d.pop("actor_type", UNSET)

        aliases = cast(list[str], d.pop("aliases", UNSET))

        origin_country = d.pop("origin_country", UNSET)

        motivation = d.pop("motivation", UNSET)

        sophistication = d.pop("sophistication", UNSET)

        active = d.pop("active", UNSET)

        create_actor_request = cls(
            name=name,
            org_id=org_id,
            actor_type=actor_type,
            aliases=aliases,
            origin_country=origin_country,
            motivation=motivation,
            sophistication=sophistication,
            active=active,
        )

        create_actor_request.additional_properties = d
        return create_actor_request

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
