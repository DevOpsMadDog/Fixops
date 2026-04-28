from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_attribution_request_evidence import CreateAttributionRequestEvidence


T = TypeVar("T", bound="CreateAttributionRequest")


@_attrs_define
class CreateAttributionRequest:
    """
    Attributes:
        incident_id (str): Incident identifier (required)
        org_id (str | Unset):  Default: 'default'.
        actor_id (str | Unset): Threat actor id (optional) Default: ''.
        confidence (str | Unset): Confidence: confirmed, likely, possible, unlikely Default: 'possible'.
        evidence (CreateAttributionRequestEvidence | Unset): Supporting evidence map
        analyst (str | Unset): Analyst who created the attribution Default: ''.
        attribution_date (None | str | Unset): ISO datetime of attribution
        notes (str | Unset): Analyst notes Default: ''.
    """

    incident_id: str
    org_id: str | Unset = "default"
    actor_id: str | Unset = ""
    confidence: str | Unset = "possible"
    evidence: CreateAttributionRequestEvidence | Unset = UNSET
    analyst: str | Unset = ""
    attribution_date: None | str | Unset = UNSET
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        incident_id = self.incident_id

        org_id = self.org_id

        actor_id = self.actor_id

        confidence = self.confidence

        evidence: dict[str, Any] | Unset = UNSET
        if not isinstance(self.evidence, Unset):
            evidence = self.evidence.to_dict()

        analyst = self.analyst

        attribution_date: None | str | Unset
        if isinstance(self.attribution_date, Unset):
            attribution_date = UNSET
        else:
            attribution_date = self.attribution_date

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "incident_id": incident_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if actor_id is not UNSET:
            field_dict["actor_id"] = actor_id
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if analyst is not UNSET:
            field_dict["analyst"] = analyst
        if attribution_date is not UNSET:
            field_dict["attribution_date"] = attribution_date
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_attribution_request_evidence import CreateAttributionRequestEvidence

        d = dict(src_dict)
        incident_id = d.pop("incident_id")

        org_id = d.pop("org_id", UNSET)

        actor_id = d.pop("actor_id", UNSET)

        confidence = d.pop("confidence", UNSET)

        _evidence = d.pop("evidence", UNSET)
        evidence: CreateAttributionRequestEvidence | Unset
        if isinstance(_evidence, Unset):
            evidence = UNSET
        else:
            evidence = CreateAttributionRequestEvidence.from_dict(_evidence)

        analyst = d.pop("analyst", UNSET)

        def _parse_attribution_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attribution_date = _parse_attribution_date(d.pop("attribution_date", UNSET))

        notes = d.pop("notes", UNSET)

        create_attribution_request = cls(
            incident_id=incident_id,
            org_id=org_id,
            actor_id=actor_id,
            confidence=confidence,
            evidence=evidence,
            analyst=analyst,
            attribution_date=attribution_date,
            notes=notes,
        )

        create_attribution_request.additional_properties = d
        return create_attribution_request

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
