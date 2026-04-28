from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCommRequest")


@_attrs_define
class CreateCommRequest:
    """
    Attributes:
        subject (str): Communication subject (required)
        body (str): Communication body content (required)
        incident_id (None | str | Unset): Associated incident ID
        comm_type (str | Unset): initial_notification | status_update | resolution | post_mortem | stakeholder_brief |
            press_release Default: 'status_update'.
        channel (str | Unset): email | slack | teams | sms | pagerduty | status_page | internal Default: 'email'.
        audience (str | Unset): internal | external | executive | technical | customer | all Default: 'internal'.
        severity (str | Unset): critical | high | medium | low Default: 'medium'.
        comm_status (str | Unset): draft | sent | delivered | failed Default: 'draft'.
        scheduled_at (None | str | Unset): Scheduled send time (ISO 8601)
        author (None | str | Unset): Author name or ID
    """

    subject: str
    body: str
    incident_id: None | str | Unset = UNSET
    comm_type: str | Unset = "status_update"
    channel: str | Unset = "email"
    audience: str | Unset = "internal"
    severity: str | Unset = "medium"
    comm_status: str | Unset = "draft"
    scheduled_at: None | str | Unset = UNSET
    author: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subject = self.subject

        body = self.body

        incident_id: None | str | Unset
        if isinstance(self.incident_id, Unset):
            incident_id = UNSET
        else:
            incident_id = self.incident_id

        comm_type = self.comm_type

        channel = self.channel

        audience = self.audience

        severity = self.severity

        comm_status = self.comm_status

        scheduled_at: None | str | Unset
        if isinstance(self.scheduled_at, Unset):
            scheduled_at = UNSET
        else:
            scheduled_at = self.scheduled_at

        author: None | str | Unset
        if isinstance(self.author, Unset):
            author = UNSET
        else:
            author = self.author

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subject": subject,
                "body": body,
            }
        )
        if incident_id is not UNSET:
            field_dict["incident_id"] = incident_id
        if comm_type is not UNSET:
            field_dict["comm_type"] = comm_type
        if channel is not UNSET:
            field_dict["channel"] = channel
        if audience is not UNSET:
            field_dict["audience"] = audience
        if severity is not UNSET:
            field_dict["severity"] = severity
        if comm_status is not UNSET:
            field_dict["comm_status"] = comm_status
        if scheduled_at is not UNSET:
            field_dict["scheduled_at"] = scheduled_at
        if author is not UNSET:
            field_dict["author"] = author

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        subject = d.pop("subject")

        body = d.pop("body")

        def _parse_incident_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        incident_id = _parse_incident_id(d.pop("incident_id", UNSET))

        comm_type = d.pop("comm_type", UNSET)

        channel = d.pop("channel", UNSET)

        audience = d.pop("audience", UNSET)

        severity = d.pop("severity", UNSET)

        comm_status = d.pop("comm_status", UNSET)

        def _parse_scheduled_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scheduled_at = _parse_scheduled_at(d.pop("scheduled_at", UNSET))

        def _parse_author(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        author = _parse_author(d.pop("author", UNSET))

        create_comm_request = cls(
            subject=subject,
            body=body,
            incident_id=incident_id,
            comm_type=comm_type,
            channel=channel,
            audience=audience,
            severity=severity,
            comm_status=comm_status,
            scheduled_at=scheduled_at,
            author=author,
        )

        create_comm_request.additional_properties = d
        return create_comm_request

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
