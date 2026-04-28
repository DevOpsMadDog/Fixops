from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.anomaly_out_details import AnomalyOutDetails


T = TypeVar("T", bound="AnomalyOut")


@_attrs_define
class AnomalyOut:
    """Serialisable anomaly record.

    Attributes:
        id (str):
        org_id (str):
        kind (str):
        severity (str):
        actor (str):
        description (str):
        entry_ids (list[str]):
        detected_at (str):
        details (AnomalyOutDetails | Unset):
    """

    id: str
    org_id: str
    kind: str
    severity: str
    actor: str
    description: str
    entry_ids: list[str]
    detected_at: str
    details: AnomalyOutDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        org_id = self.org_id

        kind = self.kind

        severity = self.severity

        actor = self.actor

        description = self.description

        entry_ids = self.entry_ids

        detected_at = self.detected_at

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "org_id": org_id,
                "kind": kind,
                "severity": severity,
                "actor": actor,
                "description": description,
                "entry_ids": entry_ids,
                "detected_at": detected_at,
            }
        )
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.anomaly_out_details import AnomalyOutDetails

        d = dict(src_dict)
        id = d.pop("id")

        org_id = d.pop("org_id")

        kind = d.pop("kind")

        severity = d.pop("severity")

        actor = d.pop("actor")

        description = d.pop("description")

        entry_ids = cast(list[str], d.pop("entry_ids"))

        detected_at = d.pop("detected_at")

        _details = d.pop("details", UNSET)
        details: AnomalyOutDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = AnomalyOutDetails.from_dict(_details)

        anomaly_out = cls(
            id=id,
            org_id=org_id,
            kind=kind,
            severity=severity,
            actor=actor,
            description=description,
            entry_ids=entry_ids,
            detected_at=detected_at,
            details=details,
        )

        anomaly_out.additional_properties = d
        return anomaly_out

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
