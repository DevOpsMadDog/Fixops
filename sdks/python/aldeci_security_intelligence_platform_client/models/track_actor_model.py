from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TrackActorModel")


@_attrs_define
class TrackActorModel:
    """
    Attributes:
        actor_name (str):
        actor_alias (str | Unset):  Default: ''.
        nation_state (str | Unset):  Default: ''.
        actor_type (str | Unset):  Default: 'unknown'.
        threat_level (str | Unset):  Default: 'medium'.
        targeting_our_sector (bool | Unset):  Default: False.
        mitre_groups (list[str] | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    actor_name: str
    actor_alias: str | Unset = ""
    nation_state: str | Unset = ""
    actor_type: str | Unset = "unknown"
    threat_level: str | Unset = "medium"
    targeting_our_sector: bool | Unset = False
    mitre_groups: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        actor_name = self.actor_name

        actor_alias = self.actor_alias

        nation_state = self.nation_state

        actor_type = self.actor_type

        threat_level = self.threat_level

        targeting_our_sector = self.targeting_our_sector

        mitre_groups: list[str] | Unset = UNSET
        if not isinstance(self.mitre_groups, Unset):
            mitre_groups = self.mitre_groups

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "actor_name": actor_name,
            }
        )
        if actor_alias is not UNSET:
            field_dict["actor_alias"] = actor_alias
        if nation_state is not UNSET:
            field_dict["nation_state"] = nation_state
        if actor_type is not UNSET:
            field_dict["actor_type"] = actor_type
        if threat_level is not UNSET:
            field_dict["threat_level"] = threat_level
        if targeting_our_sector is not UNSET:
            field_dict["targeting_our_sector"] = targeting_our_sector
        if mitre_groups is not UNSET:
            field_dict["mitre_groups"] = mitre_groups
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        actor_name = d.pop("actor_name")

        actor_alias = d.pop("actor_alias", UNSET)

        nation_state = d.pop("nation_state", UNSET)

        actor_type = d.pop("actor_type", UNSET)

        threat_level = d.pop("threat_level", UNSET)

        targeting_our_sector = d.pop("targeting_our_sector", UNSET)

        mitre_groups = cast(list[str], d.pop("mitre_groups", UNSET))

        org_id = d.pop("org_id", UNSET)

        track_actor_model = cls(
            actor_name=actor_name,
            actor_alias=actor_alias,
            nation_state=nation_state,
            actor_type=actor_type,
            threat_level=threat_level,
            targeting_our_sector=targeting_our_sector,
            mitre_groups=mitre_groups,
            org_id=org_id,
        )

        track_actor_model.additional_properties = d
        return track_actor_model

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
