from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TicketUpdate")


@_attrs_define
class TicketUpdate:
    """
    Attributes:
        title (None | str | Unset):
        severity (None | str | Unset):
        cvss_score (float | None | Unset):
        assignee_id (None | str | Unset):
        assignee_team (None | str | Unset):
        status (None | str | Unset):
        priority (None | str | Unset):
        due_date (None | str | Unset):
        resolution_notes (None | str | Unset):
        updated_by (str | Unset):  Default: 'system'.
    """

    title: None | str | Unset = UNSET
    severity: None | str | Unset = UNSET
    cvss_score: float | None | Unset = UNSET
    assignee_id: None | str | Unset = UNSET
    assignee_team: None | str | Unset = UNSET
    status: None | str | Unset = UNSET
    priority: None | str | Unset = UNSET
    due_date: None | str | Unset = UNSET
    resolution_notes: None | str | Unset = UNSET
    updated_by: str | Unset = "system"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        assignee_id: None | str | Unset
        if isinstance(self.assignee_id, Unset):
            assignee_id = UNSET
        else:
            assignee_id = self.assignee_id

        assignee_team: None | str | Unset
        if isinstance(self.assignee_team, Unset):
            assignee_team = UNSET
        else:
            assignee_team = self.assignee_team

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        priority: None | str | Unset
        if isinstance(self.priority, Unset):
            priority = UNSET
        else:
            priority = self.priority

        due_date: None | str | Unset
        if isinstance(self.due_date, Unset):
            due_date = UNSET
        else:
            due_date = self.due_date

        resolution_notes: None | str | Unset
        if isinstance(self.resolution_notes, Unset):
            resolution_notes = UNSET
        else:
            resolution_notes = self.resolution_notes

        updated_by = self.updated_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if title is not UNSET:
            field_dict["title"] = title
        if severity is not UNSET:
            field_dict["severity"] = severity
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if assignee_id is not UNSET:
            field_dict["assignee_id"] = assignee_id
        if assignee_team is not UNSET:
            field_dict["assignee_team"] = assignee_team
        if status is not UNSET:
            field_dict["status"] = status
        if priority is not UNSET:
            field_dict["priority"] = priority
        if due_date is not UNSET:
            field_dict["due_date"] = due_date
        if resolution_notes is not UNSET:
            field_dict["resolution_notes"] = resolution_notes
        if updated_by is not UNSET:
            field_dict["updated_by"] = updated_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_assignee_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee_id = _parse_assignee_id(d.pop("assignee_id", UNSET))

        def _parse_assignee_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee_team = _parse_assignee_team(d.pop("assignee_team", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_priority(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        priority = _parse_priority(d.pop("priority", UNSET))

        def _parse_due_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        due_date = _parse_due_date(d.pop("due_date", UNSET))

        def _parse_resolution_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        resolution_notes = _parse_resolution_notes(d.pop("resolution_notes", UNSET))

        updated_by = d.pop("updated_by", UNSET)

        ticket_update = cls(
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            assignee_id=assignee_id,
            assignee_team=assignee_team,
            status=status,
            priority=priority,
            due_date=due_date,
            resolution_notes=resolution_notes,
            updated_by=updated_by,
        )

        ticket_update.additional_properties = d
        return ticket_update

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
