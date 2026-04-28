from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.timeline_event_out_details import TimelineEventOutDetails


T = TypeVar("T", bound="TimelineEventOut")


@_attrs_define
class TimelineEventOut:
    """
    Attributes:
        timestamp (str):
        actor (str):
        action (str):
        resource_type (str):
        resource_id (str):
        outcome (str):
        severity (str):
        entry_id (str):
        details (TimelineEventOutDetails | Unset):
    """

    timestamp: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    severity: str
    entry_id: str
    details: TimelineEventOutDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        timestamp = self.timestamp

        actor = self.actor

        action = self.action

        resource_type = self.resource_type

        resource_id = self.resource_id

        outcome = self.outcome

        severity = self.severity

        entry_id = self.entry_id

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "timestamp": timestamp,
                "actor": actor,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "outcome": outcome,
                "severity": severity,
                "entry_id": entry_id,
            }
        )
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.timeline_event_out_details import TimelineEventOutDetails

        d = dict(src_dict)
        timestamp = d.pop("timestamp")

        actor = d.pop("actor")

        action = d.pop("action")

        resource_type = d.pop("resource_type")

        resource_id = d.pop("resource_id")

        outcome = d.pop("outcome")

        severity = d.pop("severity")

        entry_id = d.pop("entry_id")

        _details = d.pop("details", UNSET)
        details: TimelineEventOutDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = TimelineEventOutDetails.from_dict(_details)

        timeline_event_out = cls(
            timestamp=timestamp,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            severity=severity,
            entry_id=entry_id,
            details=details,
        )

        timeline_event_out.additional_properties = d
        return timeline_event_out

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
