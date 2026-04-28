from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SlackIncidentRequest")


@_attrs_define
class SlackIncidentRequest:
    """For incident notification via the API.

    Attributes:
        title (str): Incident title
        severity (str | Unset): critical | high | medium | low Default: 'high'.
        status (str | Unset): Incident status Default: 'open'.
        assignee (str | Unset): Incident assignee Default: 'Unassigned'.
        incident_id (None | str | Unset): Incident ID
        description (None | str | Unset): Incident description
    """

    title: str
    severity: str | Unset = "high"
    status: str | Unset = "open"
    assignee: str | Unset = "Unassigned"
    incident_id: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        severity = self.severity

        status = self.status

        assignee = self.assignee

        incident_id: None | str | Unset
        if isinstance(self.incident_id, Unset):
            incident_id = UNSET
        else:
            incident_id = self.incident_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if status is not UNSET:
            field_dict["status"] = status
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if incident_id is not UNSET:
            field_dict["incident_id"] = incident_id
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        severity = d.pop("severity", UNSET)

        status = d.pop("status", UNSET)

        assignee = d.pop("assignee", UNSET)

        def _parse_incident_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        incident_id = _parse_incident_id(d.pop("incident_id", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        slack_incident_request = cls(
            title=title,
            severity=severity,
            status=status,
            assignee=assignee,
            incident_id=incident_id,
            description=description,
        )

        slack_incident_request.additional_properties = d
        return slack_incident_request

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
