from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TicketCreate")


@_attrs_define
class TicketCreate:
    """
    Attributes:
        title (str):
        cve_id (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        cvss_score (float | Unset):  Default: 0.0.
        affected_assets (list[str] | Unset):
        assignee_id (str | Unset):  Default: ''.
        assignee_team (str | Unset):  Default: ''.
        priority (str | Unset):  Default: 'p3'.
        due_date (None | str | Unset):
        resolution_notes (str | Unset):  Default: ''.
        source_engine (str | Unset):  Default: 'manual'.
        tags (list[str] | Unset):
    """

    title: str
    cve_id: str | Unset = ""
    severity: str | Unset = "medium"
    cvss_score: float | Unset = 0.0
    affected_assets: list[str] | Unset = UNSET
    assignee_id: str | Unset = ""
    assignee_team: str | Unset = ""
    priority: str | Unset = "p3"
    due_date: None | str | Unset = UNSET
    resolution_notes: str | Unset = ""
    source_engine: str | Unset = "manual"
    tags: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        cve_id = self.cve_id

        severity = self.severity

        cvss_score = self.cvss_score

        affected_assets: list[str] | Unset = UNSET
        if not isinstance(self.affected_assets, Unset):
            affected_assets = self.affected_assets

        assignee_id = self.assignee_id

        assignee_team = self.assignee_team

        priority = self.priority

        due_date: None | str | Unset
        if isinstance(self.due_date, Unset):
            due_date = UNSET
        else:
            due_date = self.due_date

        resolution_notes = self.resolution_notes

        source_engine = self.source_engine

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if affected_assets is not UNSET:
            field_dict["affected_assets"] = affected_assets
        if assignee_id is not UNSET:
            field_dict["assignee_id"] = assignee_id
        if assignee_team is not UNSET:
            field_dict["assignee_team"] = assignee_team
        if priority is not UNSET:
            field_dict["priority"] = priority
        if due_date is not UNSET:
            field_dict["due_date"] = due_date
        if resolution_notes is not UNSET:
            field_dict["resolution_notes"] = resolution_notes
        if source_engine is not UNSET:
            field_dict["source_engine"] = source_engine
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        cve_id = d.pop("cve_id", UNSET)

        severity = d.pop("severity", UNSET)

        cvss_score = d.pop("cvss_score", UNSET)

        affected_assets = cast(list[str], d.pop("affected_assets", UNSET))

        assignee_id = d.pop("assignee_id", UNSET)

        assignee_team = d.pop("assignee_team", UNSET)

        priority = d.pop("priority", UNSET)

        def _parse_due_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        due_date = _parse_due_date(d.pop("due_date", UNSET))

        resolution_notes = d.pop("resolution_notes", UNSET)

        source_engine = d.pop("source_engine", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        ticket_create = cls(
            title=title,
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            affected_assets=affected_assets,
            assignee_id=assignee_id,
            assignee_team=assignee_team,
            priority=priority,
            due_date=due_date,
            resolution_notes=resolution_notes,
            source_engine=source_engine,
            tags=tags,
        )

        ticket_create.additional_properties = d
        return ticket_create

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
