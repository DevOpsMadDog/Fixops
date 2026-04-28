from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatActor")


@_attrs_define
class ThreatActor:
    """Known threat actor (APT group, criminal org, nation-state).

    Attributes:
        id: Unique actor identifier (e.g. "apt29")
        name: Common name (e.g. "Cozy Bear")
        aliases: Known alternate names
        ttps: MITRE ATT&CK technique IDs (e.g. ["T1566", "T1078"])
        motivation: Primary motivation (espionage, financial, etc.)
        origin_country: Attributed country of origin
        active: Whether actor is currently active
        associated_campaigns: Campaign IDs linked to this actor
        iocs: Indicators of Compromise (IPs, domains, hashes, etc.)

        Attributes:
            name (str):
            id (str | Unset):
            aliases (list[str] | Unset):
            ttps (list[str] | Unset):
            motivation (str | Unset):  Default: 'unknown'.
            origin_country (None | str | Unset):
            active (bool | Unset):  Default: True.
            associated_campaigns (list[str] | Unset):
            iocs (list[str] | Unset):
    """

    name: str
    id: str | Unset = UNSET
    aliases: list[str] | Unset = UNSET
    ttps: list[str] | Unset = UNSET
    motivation: str | Unset = "unknown"
    origin_country: None | str | Unset = UNSET
    active: bool | Unset = True
    associated_campaigns: list[str] | Unset = UNSET
    iocs: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        id = self.id

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        ttps: list[str] | Unset = UNSET
        if not isinstance(self.ttps, Unset):
            ttps = self.ttps

        motivation = self.motivation

        origin_country: None | str | Unset
        if isinstance(self.origin_country, Unset):
            origin_country = UNSET
        else:
            origin_country = self.origin_country

        active = self.active

        associated_campaigns: list[str] | Unset = UNSET
        if not isinstance(self.associated_campaigns, Unset):
            associated_campaigns = self.associated_campaigns

        iocs: list[str] | Unset = UNSET
        if not isinstance(self.iocs, Unset):
            iocs = self.iocs

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if aliases is not UNSET:
            field_dict["aliases"] = aliases
        if ttps is not UNSET:
            field_dict["ttps"] = ttps
        if motivation is not UNSET:
            field_dict["motivation"] = motivation
        if origin_country is not UNSET:
            field_dict["origin_country"] = origin_country
        if active is not UNSET:
            field_dict["active"] = active
        if associated_campaigns is not UNSET:
            field_dict["associated_campaigns"] = associated_campaigns
        if iocs is not UNSET:
            field_dict["iocs"] = iocs

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        id = d.pop("id", UNSET)

        aliases = cast(list[str], d.pop("aliases", UNSET))

        ttps = cast(list[str], d.pop("ttps", UNSET))

        motivation = d.pop("motivation", UNSET)

        def _parse_origin_country(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        origin_country = _parse_origin_country(d.pop("origin_country", UNSET))

        active = d.pop("active", UNSET)

        associated_campaigns = cast(list[str], d.pop("associated_campaigns", UNSET))

        iocs = cast(list[str], d.pop("iocs", UNSET))

        threat_actor = cls(
            name=name,
            id=id,
            aliases=aliases,
            ttps=ttps,
            motivation=motivation,
            origin_country=origin_country,
            active=active,
            associated_campaigns=associated_campaigns,
            iocs=iocs,
        )

        threat_actor.additional_properties = d
        return threat_actor

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
