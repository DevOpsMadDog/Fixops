from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceResponse")


@_attrs_define
class EvidenceResponse:
    """Evidence chain item response.

    Attributes:
        id (str):
        incident_id (str):
        collector_id (str):
        evidence_type (str):
        description (str):
        sha256_hash (str):
        collected_at (datetime.datetime):
        previous_hash (str):
        chain_sequence (int):
        chain_valid (bool | Unset):  Default: True.
    """

    id: str
    incident_id: str
    collector_id: str
    evidence_type: str
    description: str
    sha256_hash: str
    collected_at: datetime.datetime
    previous_hash: str
    chain_sequence: int
    chain_valid: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        incident_id = self.incident_id

        collector_id = self.collector_id

        evidence_type = self.evidence_type

        description = self.description

        sha256_hash = self.sha256_hash

        collected_at = self.collected_at.isoformat()

        previous_hash = self.previous_hash

        chain_sequence = self.chain_sequence

        chain_valid = self.chain_valid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "incident_id": incident_id,
                "collector_id": collector_id,
                "evidence_type": evidence_type,
                "description": description,
                "sha256_hash": sha256_hash,
                "collected_at": collected_at,
                "previous_hash": previous_hash,
                "chain_sequence": chain_sequence,
            }
        )
        if chain_valid is not UNSET:
            field_dict["chain_valid"] = chain_valid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        incident_id = d.pop("incident_id")

        collector_id = d.pop("collector_id")

        evidence_type = d.pop("evidence_type")

        description = d.pop("description")

        sha256_hash = d.pop("sha256_hash")

        collected_at = isoparse(d.pop("collected_at"))

        previous_hash = d.pop("previous_hash")

        chain_sequence = d.pop("chain_sequence")

        chain_valid = d.pop("chain_valid", UNSET)

        evidence_response = cls(
            id=id,
            incident_id=incident_id,
            collector_id=collector_id,
            evidence_type=evidence_type,
            description=description,
            sha256_hash=sha256_hash,
            collected_at=collected_at,
            previous_hash=previous_hash,
            chain_sequence=chain_sequence,
            chain_valid=chain_valid,
        )

        evidence_response.additional_properties = d
        return evidence_response

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
