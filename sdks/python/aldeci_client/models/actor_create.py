from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ActorCreate")


@_attrs_define
class ActorCreate:
    """
    Attributes:
        name (str):
        aliases (list[str] | Unset):
        actor_type (str | Unset):  Default: 'apt'.
        origin_country (str | Unset):  Default: ''.
        motivation (str | Unset):  Default: 'espionage'.
        sophistication (str | Unset):  Default: 'high'.
        first_observed (str | Unset):  Default: ''.
        last_observed (str | Unset):  Default: ''.
        active (bool | Unset):  Default: True.
        threat_score (float | Unset):  Default: 0.0.
        mitre_group_id (str | Unset):  Default: ''.
    """

    name: str
    aliases: list[str] | Unset = UNSET
    actor_type: str | Unset = "apt"
    origin_country: str | Unset = ""
    motivation: str | Unset = "espionage"
    sophistication: str | Unset = "high"
    first_observed: str | Unset = ""
    last_observed: str | Unset = ""
    active: bool | Unset = True
    threat_score: float | Unset = 0.0
    mitre_group_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        actor_type = self.actor_type

        origin_country = self.origin_country

        motivation = self.motivation

        sophistication = self.sophistication

        first_observed = self.first_observed

        last_observed = self.last_observed

        active = self.active

        threat_score = self.threat_score

        mitre_group_id = self.mitre_group_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if actor_type is not UNSET:
            field_dict["actor_type"] = actor_type
        if origin_country is not UNSET:
            field_dict["origin_country"] = origin_country
        if motivation is not UNSET:
            field_dict["motivation"] = motivation
        if sophistication is not UNSET:
            field_dict["sophistication"] = sophistication
        if first_observed is not UNSET:
            field_dict["first_observed"] = first_observed
        if last_observed is not UNSET:
            field_dict["last_observed"] = last_observed
        if active is not UNSET:
            field_dict["active"] = active
        if threat_score is not UNSET:
            field_dict["threat_score"] = threat_score
        if mitre_group_id is not UNSET:
            field_dict["mitre_group_id"] = mitre_group_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        aliases = cast(list[str], d.pop("aliases", UNSET))

        actor_type = d.pop("actor_type", UNSET)

        origin_country = d.pop("origin_country", UNSET)

        motivation = d.pop("motivation", UNSET)

        sophistication = d.pop("sophistication", UNSET)

        first_observed = d.pop("first_observed", UNSET)

        last_observed = d.pop("last_observed", UNSET)

        active = d.pop("active", UNSET)

        threat_score = d.pop("threat_score", UNSET)

        mitre_group_id = d.pop("mitre_group_id", UNSET)

        actor_create = cls(
            name=name,
            aliases=aliases,
            actor_type=actor_type,
            origin_country=origin_country,
            motivation=motivation,
            sophistication=sophistication,
            first_observed=first_observed,
            last_observed=last_observed,
            active=active,
            threat_score=threat_score,
            mitre_group_id=mitre_group_id,
        )

        actor_create.additional_properties = d
        return actor_create

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
