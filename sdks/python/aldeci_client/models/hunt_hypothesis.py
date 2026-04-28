from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.hunt_severity import HuntSeverity
from ..models.kill_chain_phase import KillChainPhase
from ..models.mitre_tactic import MitreTactic
from ..types import UNSET, Unset

T = TypeVar("T", bound="HuntHypothesis")


@_attrs_define
class HuntHypothesis:
    """A pre-built or custom hunt hypothesis.

    Attributes:
        name (str):
        description (str):
        mitre_tactic (MitreTactic):
        mitre_technique_id (str):
        mitre_technique_name (str):
        kill_chain_phase (KillChainPhase):
        severity (HuntSeverity):
        id (str | Unset):
        data_sources (list[str] | Unset):
        search_query (str | Unset):  Default: ''.
        tags (list[str] | Unset):
        created_at (datetime.datetime | Unset):
    """

    name: str
    description: str
    mitre_tactic: MitreTactic
    mitre_technique_id: str
    mitre_technique_name: str
    kill_chain_phase: KillChainPhase
    severity: HuntSeverity
    id: str | Unset = UNSET
    data_sources: list[str] | Unset = UNSET
    search_query: str | Unset = ""
    tags: list[str] | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        mitre_tactic = self.mitre_tactic.value

        mitre_technique_id = self.mitre_technique_id

        mitre_technique_name = self.mitre_technique_name

        kill_chain_phase = self.kill_chain_phase.value

        severity = self.severity.value

        id = self.id

        data_sources: list[str] | Unset = UNSET
        if not isinstance(self.data_sources, Unset):
            data_sources = self.data_sources

        search_query = self.search_query

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
                "description": description,
                "mitre_tactic": mitre_tactic,
                "mitre_technique_id": mitre_technique_id,
                "mitre_technique_name": mitre_technique_name,
                "kill_chain_phase": kill_chain_phase,
                "severity": severity,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if data_sources is not UNSET:
            field_dict["data_sources"] = data_sources
        if search_query is not UNSET:
            field_dict["search_query"] = search_query
        if tags is not UNSET:
            field_dict["tags"] = tags
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description")

        mitre_tactic = MitreTactic(d.pop("mitre_tactic"))

        mitre_technique_id = d.pop("mitre_technique_id")

        mitre_technique_name = d.pop("mitre_technique_name")

        kill_chain_phase = KillChainPhase(d.pop("kill_chain_phase"))

        severity = HuntSeverity(d.pop("severity"))

        id = d.pop("id", UNSET)

        data_sources = cast(list[str], d.pop("data_sources", UNSET))

        search_query = d.pop("search_query", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        hunt_hypothesis = cls(
            name=name,
            description=description,
            mitre_tactic=mitre_tactic,
            mitre_technique_id=mitre_technique_id,
            mitre_technique_name=mitre_technique_name,
            kill_chain_phase=kill_chain_phase,
            severity=severity,
            id=id,
            data_sources=data_sources,
            search_query=search_query,
            tags=tags,
            created_at=created_at,
        )

        hunt_hypothesis.additional_properties = d
        return hunt_hypothesis

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
