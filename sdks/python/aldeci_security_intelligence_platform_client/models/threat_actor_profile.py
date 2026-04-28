from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.threat_actor_motivation import ThreatActorMotivation
from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatActorProfile")


@_attrs_define
class ThreatActorProfile:
    """A known threat actor profile.

    Attributes:
        name (str):
        id (str | Unset):
        aliases (list[str] | Unset):
        motivation (ThreatActorMotivation | Unset):
        description (str | Unset):  Default: ''.
        targeted_industries (list[str] | Unset):
        targeted_regions (list[str] | Unset):
        mitre_techniques (list[str] | Unset):
        associated_ioc_ids (list[str] | Unset):
        first_observed (datetime.datetime | None | Unset):
        last_active (datetime.datetime | None | Unset):
        sophistication (str | Unset):  Default: 'unknown'.
        tags (list[str] | Unset):
        created_at (datetime.datetime | Unset):
    """

    name: str
    id: str | Unset = UNSET
    aliases: list[str] | Unset = UNSET
    motivation: ThreatActorMotivation | Unset = UNSET
    description: str | Unset = ""
    targeted_industries: list[str] | Unset = UNSET
    targeted_regions: list[str] | Unset = UNSET
    mitre_techniques: list[str] | Unset = UNSET
    associated_ioc_ids: list[str] | Unset = UNSET
    first_observed: datetime.datetime | None | Unset = UNSET
    last_active: datetime.datetime | None | Unset = UNSET
    sophistication: str | Unset = "unknown"
    tags: list[str] | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        id = self.id

        aliases: list[str] | Unset = UNSET
        if not isinstance(self.aliases, Unset):
            aliases = self.aliases

        motivation: str | Unset = UNSET
        if not isinstance(self.motivation, Unset):
            motivation = self.motivation.value

        description = self.description

        targeted_industries: list[str] | Unset = UNSET
        if not isinstance(self.targeted_industries, Unset):
            targeted_industries = self.targeted_industries

        targeted_regions: list[str] | Unset = UNSET
        if not isinstance(self.targeted_regions, Unset):
            targeted_regions = self.targeted_regions

        mitre_techniques: list[str] | Unset = UNSET
        if not isinstance(self.mitre_techniques, Unset):
            mitre_techniques = self.mitre_techniques

        associated_ioc_ids: list[str] | Unset = UNSET
        if not isinstance(self.associated_ioc_ids, Unset):
            associated_ioc_ids = self.associated_ioc_ids

        first_observed: None | str | Unset
        if isinstance(self.first_observed, Unset):
            first_observed = UNSET
        elif isinstance(self.first_observed, datetime.datetime):
            first_observed = self.first_observed.isoformat()
        else:
            first_observed = self.first_observed

        last_active: None | str | Unset
        if isinstance(self.last_active, Unset):
            last_active = UNSET
        elif isinstance(self.last_active, datetime.datetime):
            last_active = self.last_active.isoformat()
        else:
            last_active = self.last_active

        sophistication = self.sophistication

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

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
        if motivation is not UNSET:
            field_dict["motivation"] = motivation
        if description is not UNSET:
            field_dict["description"] = description
        if targeted_industries is not UNSET:
            field_dict["targeted_industries"] = targeted_industries
        if targeted_regions is not UNSET:
            field_dict["targeted_regions"] = targeted_regions
        if mitre_techniques is not UNSET:
            field_dict["mitre_techniques"] = mitre_techniques
        if associated_ioc_ids is not UNSET:
            field_dict["associated_ioc_ids"] = associated_ioc_ids
        if first_observed is not UNSET:
            field_dict["first_observed"] = first_observed
        if last_active is not UNSET:
            field_dict["last_active"] = last_active
        if sophistication is not UNSET:
            field_dict["sophistication"] = sophistication
        if tags is not UNSET:
            field_dict["tags"] = tags
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        id = d.pop("id", UNSET)

        aliases = cast(list[str], d.pop("aliases", UNSET))

        _motivation = d.pop("motivation", UNSET)
        motivation: ThreatActorMotivation | Unset
        if isinstance(_motivation, Unset):
            motivation = UNSET
        else:
            motivation = ThreatActorMotivation(_motivation)

        description = d.pop("description", UNSET)

        targeted_industries = cast(list[str], d.pop("targeted_industries", UNSET))

        targeted_regions = cast(list[str], d.pop("targeted_regions", UNSET))

        mitre_techniques = cast(list[str], d.pop("mitre_techniques", UNSET))

        associated_ioc_ids = cast(list[str], d.pop("associated_ioc_ids", UNSET))

        def _parse_first_observed(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                first_observed_type_0 = isoparse(data)

                return first_observed_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        first_observed = _parse_first_observed(d.pop("first_observed", UNSET))

        def _parse_last_active(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_active_type_0 = isoparse(data)

                return last_active_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        last_active = _parse_last_active(d.pop("last_active", UNSET))

        sophistication = d.pop("sophistication", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        threat_actor_profile = cls(
            name=name,
            id=id,
            aliases=aliases,
            motivation=motivation,
            description=description,
            targeted_industries=targeted_industries,
            targeted_regions=targeted_regions,
            mitre_techniques=mitre_techniques,
            associated_ioc_ids=associated_ioc_ids,
            first_observed=first_observed,
            last_active=last_active,
            sophistication=sophistication,
            tags=tags,
            created_at=created_at,
        )

        threat_actor_profile.additional_properties = d
        return threat_actor_profile

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
