from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.hunt_severity import HuntSeverity
from ..models.kill_chain_phase import KillChainPhase
from ..types import UNSET, Unset

T = TypeVar("T", bound="HuntFinding")


@_attrs_define
class HuntFinding:
    """A finding discovered during a hunt.

    Attributes:
        hunt_id (str):
        title (str):
        severity (HuntSeverity):
        id (str | Unset):
        description (str | Unset):  Default: ''.
        mitre_technique_id (str | Unset):  Default: ''.
        evidence (list[str] | Unset):
        ioc_matches (list[str] | Unset):
        kill_chain_phase (KillChainPhase | None | Unset):
        created_at (datetime.datetime | Unset):
    """

    hunt_id: str
    title: str
    severity: HuntSeverity
    id: str | Unset = UNSET
    description: str | Unset = ""
    mitre_technique_id: str | Unset = ""
    evidence: list[str] | Unset = UNSET
    ioc_matches: list[str] | Unset = UNSET
    kill_chain_phase: KillChainPhase | None | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hunt_id = self.hunt_id

        title = self.title

        severity = self.severity.value

        id = self.id

        description = self.description

        mitre_technique_id = self.mitre_technique_id

        evidence: list[str] | Unset = UNSET
        if not isinstance(self.evidence, Unset):
            evidence = self.evidence

        ioc_matches: list[str] | Unset = UNSET
        if not isinstance(self.ioc_matches, Unset):
            ioc_matches = self.ioc_matches

        kill_chain_phase: None | str | Unset
        if isinstance(self.kill_chain_phase, Unset):
            kill_chain_phase = UNSET
        elif isinstance(self.kill_chain_phase, KillChainPhase):
            kill_chain_phase = self.kill_chain_phase.value
        else:
            kill_chain_phase = self.kill_chain_phase

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hunt_id": hunt_id,
                "title": title,
                "severity": severity,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if description is not UNSET:
            field_dict["description"] = description
        if mitre_technique_id is not UNSET:
            field_dict["mitre_technique_id"] = mitre_technique_id
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if ioc_matches is not UNSET:
            field_dict["ioc_matches"] = ioc_matches
        if kill_chain_phase is not UNSET:
            field_dict["kill_chain_phase"] = kill_chain_phase
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        hunt_id = d.pop("hunt_id")

        title = d.pop("title")

        severity = HuntSeverity(d.pop("severity"))

        id = d.pop("id", UNSET)

        description = d.pop("description", UNSET)

        mitre_technique_id = d.pop("mitre_technique_id", UNSET)

        evidence = cast(list[str], d.pop("evidence", UNSET))

        ioc_matches = cast(list[str], d.pop("ioc_matches", UNSET))

        def _parse_kill_chain_phase(data: object) -> KillChainPhase | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                kill_chain_phase_type_0 = KillChainPhase(data)

                return kill_chain_phase_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(KillChainPhase | None | Unset, data)

        kill_chain_phase = _parse_kill_chain_phase(d.pop("kill_chain_phase", UNSET))

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        hunt_finding = cls(
            hunt_id=hunt_id,
            title=title,
            severity=severity,
            id=id,
            description=description,
            mitre_technique_id=mitre_technique_id,
            evidence=evidence,
            ioc_matches=ioc_matches,
            kill_chain_phase=kill_chain_phase,
            created_at=created_at,
        )

        hunt_finding.additional_properties = d
        return hunt_finding

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
