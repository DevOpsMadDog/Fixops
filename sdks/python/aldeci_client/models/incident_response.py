from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.incident_response_context import IncidentResponseContext
    from ..models.incident_response_current_phase_steps_item import IncidentResponseCurrentPhaseStepsItem
    from ..models.incident_response_phase_history_item import IncidentResponsePhaseHistoryItem


T = TypeVar("T", bound="IncidentResponse")


@_attrs_define
class IncidentResponse:
    """Full incident response model.

    Attributes:
        id (str):
        playbook_id (str):
        title (str):
        incident_type (str):
        severity (str):
        status (str):
        current_phase (str):
        org_id (str):
        assigned_to (None | str):
        affected_systems (list[str]):
        affected_users (list[str]):
        tags (list[str]):
        phase_history (list[IncidentResponsePhaseHistoryItem]):
        context (IncidentResponseContext):
        created_at (datetime.datetime):
        detected_at (datetime.datetime | None):
        contained_at (datetime.datetime | None):
        resolved_at (datetime.datetime | None):
        updated_at (datetime.datetime):
        current_phase_steps (list[IncidentResponseCurrentPhaseStepsItem]):
    """

    id: str
    playbook_id: str
    title: str
    incident_type: str
    severity: str
    status: str
    current_phase: str
    org_id: str
    assigned_to: None | str
    affected_systems: list[str]
    affected_users: list[str]
    tags: list[str]
    phase_history: list[IncidentResponsePhaseHistoryItem]
    context: IncidentResponseContext
    created_at: datetime.datetime
    detected_at: datetime.datetime | None
    contained_at: datetime.datetime | None
    resolved_at: datetime.datetime | None
    updated_at: datetime.datetime
    current_phase_steps: list[IncidentResponseCurrentPhaseStepsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        playbook_id = self.playbook_id

        title = self.title

        incident_type = self.incident_type

        severity = self.severity

        status = self.status

        current_phase = self.current_phase

        org_id = self.org_id

        assigned_to: None | str
        assigned_to = self.assigned_to

        affected_systems = self.affected_systems

        affected_users = self.affected_users

        tags = self.tags

        phase_history = []
        for phase_history_item_data in self.phase_history:
            phase_history_item = phase_history_item_data.to_dict()
            phase_history.append(phase_history_item)

        context = self.context.to_dict()

        created_at = self.created_at.isoformat()

        detected_at: None | str
        if isinstance(self.detected_at, datetime.datetime):
            detected_at = self.detected_at.isoformat()
        else:
            detected_at = self.detected_at

        contained_at: None | str
        if isinstance(self.contained_at, datetime.datetime):
            contained_at = self.contained_at.isoformat()
        else:
            contained_at = self.contained_at

        resolved_at: None | str
        if isinstance(self.resolved_at, datetime.datetime):
            resolved_at = self.resolved_at.isoformat()
        else:
            resolved_at = self.resolved_at

        updated_at = self.updated_at.isoformat()

        current_phase_steps = []
        for current_phase_steps_item_data in self.current_phase_steps:
            current_phase_steps_item = current_phase_steps_item_data.to_dict()
            current_phase_steps.append(current_phase_steps_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "playbook_id": playbook_id,
                "title": title,
                "incident_type": incident_type,
                "severity": severity,
                "status": status,
                "current_phase": current_phase,
                "org_id": org_id,
                "assigned_to": assigned_to,
                "affected_systems": affected_systems,
                "affected_users": affected_users,
                "tags": tags,
                "phase_history": phase_history,
                "context": context,
                "created_at": created_at,
                "detected_at": detected_at,
                "contained_at": contained_at,
                "resolved_at": resolved_at,
                "updated_at": updated_at,
                "current_phase_steps": current_phase_steps,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.incident_response_context import IncidentResponseContext
        from ..models.incident_response_current_phase_steps_item import IncidentResponseCurrentPhaseStepsItem
        from ..models.incident_response_phase_history_item import IncidentResponsePhaseHistoryItem

        d = dict(src_dict)
        id = d.pop("id")

        playbook_id = d.pop("playbook_id")

        title = d.pop("title")

        incident_type = d.pop("incident_type")

        severity = d.pop("severity")

        status = d.pop("status")

        current_phase = d.pop("current_phase")

        org_id = d.pop("org_id")

        def _parse_assigned_to(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        assigned_to = _parse_assigned_to(d.pop("assigned_to"))

        affected_systems = cast(list[str], d.pop("affected_systems"))

        affected_users = cast(list[str], d.pop("affected_users"))

        tags = cast(list[str], d.pop("tags"))

        phase_history = []
        _phase_history = d.pop("phase_history")
        for phase_history_item_data in _phase_history:
            phase_history_item = IncidentResponsePhaseHistoryItem.from_dict(phase_history_item_data)

            phase_history.append(phase_history_item)

        context = IncidentResponseContext.from_dict(d.pop("context"))

        created_at = isoparse(d.pop("created_at"))

        def _parse_detected_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                detected_at_type_0 = isoparse(data)

                return detected_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        detected_at = _parse_detected_at(d.pop("detected_at"))

        def _parse_contained_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                contained_at_type_0 = isoparse(data)

                return contained_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        contained_at = _parse_contained_at(d.pop("contained_at"))

        def _parse_resolved_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                resolved_at_type_0 = isoparse(data)

                return resolved_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        resolved_at = _parse_resolved_at(d.pop("resolved_at"))

        updated_at = isoparse(d.pop("updated_at"))

        current_phase_steps = []
        _current_phase_steps = d.pop("current_phase_steps")
        for current_phase_steps_item_data in _current_phase_steps:
            current_phase_steps_item = IncidentResponseCurrentPhaseStepsItem.from_dict(current_phase_steps_item_data)

            current_phase_steps.append(current_phase_steps_item)

        incident_response = cls(
            id=id,
            playbook_id=playbook_id,
            title=title,
            incident_type=incident_type,
            severity=severity,
            status=status,
            current_phase=current_phase,
            org_id=org_id,
            assigned_to=assigned_to,
            affected_systems=affected_systems,
            affected_users=affected_users,
            tags=tags,
            phase_history=phase_history,
            context=context,
            created_at=created_at,
            detected_at=detected_at,
            contained_at=contained_at,
            resolved_at=resolved_at,
            updated_at=updated_at,
            current_phase_steps=current_phase_steps,
        )

        incident_response.additional_properties = d
        return incident_response

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
