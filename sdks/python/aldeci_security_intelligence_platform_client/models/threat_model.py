from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatModel")


@_attrs_define
class ThreatModel:
    """A threat model document describing a system under analysis.

    Contains the system description, data flow, trust boundaries, and
    references to all identified ThreatEntry records.

        Attributes:
            name (str): Threat model name
            system_description (str): Description of the system being modeled
            id (str | Unset):
            data_flow_description (str | Unset): Data flow summary (DFD narrative) Default: ''.
            trust_boundaries (list[str] | Unset): Trust boundary labels
            threats (list[str] | Unset): List of ThreatEntry IDs
            created_at (datetime.datetime | Unset):
            org_id (str | Unset): Organisation identifier Default: 'default'.
    """

    name: str
    system_description: str
    id: str | Unset = UNSET
    data_flow_description: str | Unset = ""
    trust_boundaries: list[str] | Unset = UNSET
    threats: list[str] | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        system_description = self.system_description

        id = self.id

        data_flow_description = self.data_flow_description

        trust_boundaries: list[str] | Unset = UNSET
        if not isinstance(self.trust_boundaries, Unset):
            trust_boundaries = self.trust_boundaries

        threats: list[str] | Unset = UNSET
        if not isinstance(self.threats, Unset):
            threats = self.threats

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "system_description": system_description,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if data_flow_description is not UNSET:
            field_dict["data_flow_description"] = data_flow_description
        if trust_boundaries is not UNSET:
            field_dict["trust_boundaries"] = trust_boundaries
        if threats is not UNSET:
            field_dict["threats"] = threats
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        system_description = d.pop("system_description")

        id = d.pop("id", UNSET)

        data_flow_description = d.pop("data_flow_description", UNSET)

        trust_boundaries = cast(list[str], d.pop("trust_boundaries", UNSET))

        threats = cast(list[str], d.pop("threats", UNSET))

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        org_id = d.pop("org_id", UNSET)

        threat_model = cls(
            name=name,
            system_description=system_description,
            id=id,
            data_flow_description=data_flow_description,
            trust_boundaries=trust_boundaries,
            threats=threats,
            created_at=created_at,
            org_id=org_id,
        )

        threat_model.additional_properties = d
        return threat_model

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
